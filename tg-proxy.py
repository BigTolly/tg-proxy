#!/usr/bin/env python3
"""Telegram MTProto WebSocket Proxy.

Key insight from Flowseal/tg-ws-proxy:
- Client sends init packet encrypted with SHA256(prekey + SECRET)
- We decrypt it, extract DC ID and proto tag
- We generate NEW relay_init for Telegram (raw key, no secret hash)
- All subsequent traffic is re-encrypted: client cipher <-> telegram cipher
- Connect DIRECTLY to kws*.web.telegram.org via TLS (no Cloudflare Worker!)
"""
import asyncio
import configparser
import hashlib
import logging
import signal
import socket
import struct
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from crypto import AesCtr
from raw_ws import RawWebSocket, WsError
from fake_tls import (
    TLS_HANDSHAKE, verify_client_hello, build_server_hello,
    FakeTlsStream, proxy_to_masking_domain, connect_fake_tls
)

log = logging.getLogger('tg-proxy')

HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b'\xef\xef\xef\xef'
PROTO_TAG_INTERMEDIATE = b'\xee\xee\xee\xee'
PROTO_TAG_SECURE = b'\xdd\xdd\xdd\xdd'

PROTO_ABRIDGED_INT = 0xEFEFEFEF
PROTO_INTERMEDIATE_INT = 0xEEEEEEEE
PROTO_PADDED_INT = 0xDDDDDDDD

RESERVED_FIRST_BYTES = {0xEF}
RESERVED_STARTS = {b'\x48\x45\x41\x44', b'\x50\x4F\x53\x54',
                   b'\x47\x45\x54\x20', b'\xee\xee\xee\xee',
                   b'\xdd\xdd\xdd\xdd', b'\x16\x03\x01\x02'}
RESERVED_CONTINUE = b'\x00\x00\x00\x00'

# Telegram DC IPs for direct connection
DC_IPS = {
    1: '149.154.175.50',
    2: '149.154.167.51',
    3: '149.154.175.100',
    4: '149.154.167.91',
    5: '149.154.171.5',
    203: '91.105.192.100',
}

# WS connection pool
WS_POOL_MAX_AGE = 120.0
WS_POOL_SIZE = 4


class WsPool:
    """Pre-connected WebSocket pool for reduced latency."""
    def __init__(self):
        self._idle = {}  # (dc, is_media) -> deque of (ws, created_time)
        self._refilling = set()
        import time
        self._time = time.monotonic

    async def get(self, dc: int, is_media: bool, target_ip: str, domains: list):
        """Get WS from pool or None if empty."""
        from collections import deque
        key = (dc, is_media)
        now = self._time()

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket

        while bucket:
            ws, created = bucket.popleft()
            age = now - created
            if age > WS_POOL_MAX_AGE or ws._closed:
                asyncio.create_task(self._quiet_close(ws))
                continue
            log.debug(f'Pool hit DC{dc}{"m" if is_media else ""} (age={age:.1f}s)')
            self._schedule_refill(key, target_ip, domains)
            return ws

        self._schedule_refill(key, target_ip, domains)
        return None

    def _schedule_refill(self, key, target_ip, domains):
        if key in self._refilling:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip, domains):
        from collections import deque
        dc, is_media = key
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = WS_POOL_SIZE - len(bucket)
            if needed <= 0:
                return
            for _ in range(needed):
                ws = await self._connect_one(target_ip, domains)
                if ws:
                    bucket.append((ws, self._time()))
            log.debug(f'Pool refill DC{dc}{"m" if is_media else ""}: {len(bucket)} ready')
        finally:
            self._refilling.discard(key)

    @staticmethod
    async def _connect_one(target_ip, domains):
        for domain in domains:
            try:
                return await RawWebSocket.connect(target_ip, '/apiws', timeout=8,
                                                   sni=domain, http_host=domain)
            except WsError as e:
                if e.is_redirect:
                    continue
                return None
            except:
                return None
        return None

    @staticmethod
    async def _quiet_close(ws):
        try:
            await ws.close()
        except:
            pass

    async def warmup(self, dc_ips: dict):
        """Pre-fill pool for all DCs."""
        for dc, ip in dc_ips.items():
            for is_media in (False, True):
                domains = _ws_domains(dc, is_media)
                self._schedule_refill((dc, is_media), ip, domains)
        log.info(f'Pool warmup started for {len(dc_ips)} DCs')

    def reset(self):
        self._idle.clear()
        self._refilling.clear()


ws_pool = WsPool()


class MsgSplitter:
    """Splits TCP stream into MTProto packets for separate WS frames."""
    def __init__(self, relay_init: bytes, proto_int: int):
        cipher = AesCtr(relay_init[8:40], relay_init[40:56])
        cipher.process(b'\x00' * 64)  # skip init
        self._dec = cipher
        self._proto = proto_int
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes) -> list:
        if not chunk:
            return []
        if self._disabled:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._dec.process(chunk))

        parts = []
        while self._cipher_buf:
            plen = self._next_packet_len()
            if plen is None:
                break
            if plen <= 0:
                parts.append(bytes(self._cipher_buf))
                self._cipher_buf.clear()
                self._plain_buf.clear()
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[:plen]))
            del self._cipher_buf[:plen]
            del self._plain_buf[:plen]
        return parts

    def flush(self) -> list:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self):
        if not self._plain_buf:
            return None
        if self._proto == PROTO_ABRIDGED_INT:
            return self._next_abridged()
        if self._proto in (PROTO_INTERMEDIATE_INT, PROTO_PADDED_INT):
            return self._next_intermediate()
        return 0

    def _next_abridged(self):
        first = self._plain_buf[0]
        if first in (0x7F, 0xFF):
            if len(self._plain_buf) < 4:
                return None
            payload_len = int.from_bytes(self._plain_buf[1:4], 'little') * 4
            header_len = 4
        else:
            payload_len = (first & 0x7F) * 4
            header_len = 1
        if payload_len <= 0:
            return 0
        packet_len = header_len + payload_len
        if len(self._plain_buf) < packet_len:
            return None
        return packet_len

    def _next_intermediate(self):
        if len(self._plain_buf) < 4:
            return None
        payload_len = struct.unpack('<I', bytes(self._plain_buf[:4]))[0] & 0x7FFFFFFF
        if payload_len <= 0:
            return 0
        packet_len = 4 + payload_len
        if len(self._plain_buf) < packet_len:
            return None
        return packet_len


def _ws_domains(dc: int, is_media: bool) -> list:
    """Get WS domain list for DC (media-optimized first if is_media)."""
    if dc == 203:
        dc = 2
    if is_media:
        return [f'kws{dc}-1.web.telegram.org', f'kws{dc}.web.telegram.org']
    return [f'kws{dc}.web.telegram.org', f'kws{dc}-1.web.telegram.org']


class KeyConfig:
    """Single key configuration."""
    def __init__(self, secret: bytes, fake_tls_domain: str = ''):
        self.secret = secret
        self.fake_tls_domain = fake_tls_domain

    @property
    def is_fake_tls(self) -> bool:
        return bool(self.fake_tls_domain)


class UpstreamConfig:
    """Remote tg-proxy used as a tunnel for DCs that are unreachable directly."""
    def __init__(self, host, port, secret, domain, dcs, fallback, media: bool = True):
        self.host = host
        self.port = port
        self.secret = secret
        self.domain = domain      # non-empty -> Fake TLS (ee) to upstream
        self.dcs = dcs            # DCs always routed via upstream
        self.fallback = fallback  # also use upstream when WS fails
        self.media = media        # route all media connections (is_media) to upstream


class Config:
    def __init__(self, path: str = 'config.ini'):
        self.cfg = configparser.ConfigParser()
        self.cfg.read(path)
        raw_ip = self.cfg.get('server', 'ip', fallback='0.0.0.0').strip()
        self.ip = raw_ip
        if raw_ip in ('*', 'all', 'any', ''):
            self.bind_hosts = ['0.0.0.0', '::']
        elif ',' in raw_ip:
            self.bind_hosts = [h.strip() for h in raw_ip.split(',') if h.strip()]
        else:
            self.bind_hosts = raw_ip
        self.verbose = self.cfg.getboolean('server', 'verbose', fallback=False)

        # DC IPs from config or defaults
        self.dc_ips = dict(DC_IPS)
        if 'datacenters' in self.cfg:
            for dc_id, val in self.cfg['datacenters'].items():
                self.dc_ips[int(dc_id)] = val.strip()


        # Upstream chaining: send selected DCs through a remote tg-proxy
        self.upstream = None
        if 'upstream' in self.cfg:
            u = self.cfg['upstream']
            host = u.get('host', '').strip()
            if host:
                try:
                    dcs = {int(x) for x in u.get('dcs', '').replace(' ', '').split(',') if x}
                    self.upstream = UpstreamConfig(
                        host=host,
                        port=int(u.get('port', '443')),
                        secret=bytes.fromhex(u.get('secret', '').strip()),
                        domain=u.get('domain', '').strip(),
                        dcs=dcs,
                        fallback=u.getboolean('fallback', True),
                        media=u.getboolean('media', True),
                    )
                except ValueError as e:
                    raise SystemExit(f'config.ini [upstream]: invalid value: {e}')

        # Parse keys: port -> list of KeyConfig
        # Format in [keys] section: key1 = port:secret or key1 = port:secret:fake_tls_domain
        self.listeners = {}  # port -> [KeyConfig, ...]
        if 'keys' in self.cfg:
            for key_name, value in self.cfg.items('keys'):
                parts = value.strip().split(':')
                if len(parts) < 2:
                    continue
                try:
                    port = int(parts[0])
                    secret = bytes.fromhex(parts[1])
                except (ValueError, IndexError):
                    continue
                fake_tls = parts[2] if len(parts) > 2 else ''
                if port not in self.listeners:
                    self.listeners[port] = []
                self.listeners[port].append(KeyConfig(secret, fake_tls))

        # Fallback to old [server] format if no [keys]
        if not self.listeners:
            port = self.cfg.getint('server', 'port', fallback=1080)
            secret = bytes.fromhex(self.cfg.get('server', 'secret', fallback='0'*32))
            fake_tls = self.cfg.get('server', 'fake_tls_domain', fallback='')
            self.listeners[port] = [KeyConfig(secret, fake_tls)]

    def get_ports(self) -> list:
        return list(self.listeners.keys())

    def get_keys(self, port: int) -> list:
        return self.listeners.get(port, [])


class CryptoCtx:
    """Re-encryption context between client and Telegram."""
    def __init__(self, clt_dec: AesCtr, clt_enc: AesCtr,
                 tg_enc: AesCtr, tg_dec: AesCtr):
        self.clt_dec = clt_dec  # decrypt from client
        self.clt_enc = clt_enc  # encrypt to client
        self.tg_enc = tg_enc    # encrypt to telegram
        self.tg_dec = tg_dec    # decrypt from telegram


def parse_handshake(data: bytes, secret: bytes):
    """Parse MTProto obfuscation handshake.

    Returns (dc_id, is_media, proto_tag) or None if invalid.
    """
    if len(data) < HANDSHAKE_LEN:
        return None

    dec_prekey = data[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    dec_iv = data[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    dec_key = hashlib.sha256(dec_prekey + secret).digest()

    cipher = AesCtr(dec_key, dec_iv)
    decrypted = cipher.process(data)

    # DEBUG: показать raw DC bytes
    dc_raw = decrypted[DC_IDX_POS:DC_IDX_POS + 2]
    log.debug(f'DC raw bytes: {dc_raw.hex()} → {struct.unpack("<h", dc_raw)[0]}')

    proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS + 4]
    if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
        return None

    dc_idx = struct.unpack('<h', decrypted[DC_IDX_POS:DC_IDX_POS + 2])[0]
    dc_id = abs(dc_idx)
    is_media = dc_idx < 0

    return dc_id, is_media, proto_tag


def generate_relay_init(proto_tag: bytes, dc_idx: int) -> bytes:
    """Generate relay init packet for Telegram (without secret hash)."""
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if rnd[4:8] == RESERVED_CONTINUE:
            continue
        break

    enc_key = bytes(rnd[SKIP_LEN:SKIP_LEN + PREKEY_LEN])
    enc_iv = bytes(rnd[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN])

    cipher = AesCtr(enc_key, enc_iv)
    encrypted_full = cipher.process(bytes(rnd))

    dc_bytes = struct.pack('<h', dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)

    # XOR tail with keystream
    keystream_tail = bytes(encrypted_full[i] ^ rnd[i] for i in range(56, 64))
    encrypted_tail = bytes(tail_plain[i] ^ keystream_tail[i] for i in range(8))

    rnd[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(rnd)


def generate_client_init(proto_tag: bytes, dc_idx: int, secret: bytes):
    """Generate obfuscated2 init as a *client* of another proxy.

    Returns (init, enc, dec): enc encrypts data sent to the proxy (already
    advanced past the init), dec decrypts data coming from the proxy.
    """
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if rnd[4:8] == RESERVED_CONTINUE:
            continue
        break

    prekey = bytes(rnd[SKIP_LEN:SKIP_LEN + PREKEY_LEN])
    iv = bytes(rnd[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN])

    enc_key = hashlib.sha256(prekey + secret).digest()
    probe = AesCtr(enc_key, iv)
    keystream = probe.process(bytes(rnd))           # keystream XOR rnd
    tail_plain = proto_tag + struct.pack('<h', dc_idx) + os.urandom(2)
    tail = bytes(tail_plain[i] ^ keystream[56 + i] ^ rnd[56 + i] for i in range(8))
    rnd[PROTO_TAG_POS:HANDSHAKE_LEN] = tail

    enc = AesCtr(enc_key, iv)
    enc.process(b'\x00' * HANDSHAKE_LEN)             # skip init

    rev = (prekey + iv)[::-1]
    dec = AesCtr(hashlib.sha256(rev[:PREKEY_LEN] + secret).digest(), rev[PREKEY_LEN:])
    return bytes(rnd), enc, dec


async def open_upstream(up: 'UpstreamConfig', proto_tag: bytes, dc_idx: int):
    """Connect to upstream tg-proxy. Returns (reader, writer, enc, dec)."""
    if up.domain:
        stream = await connect_fake_tls(up.host, up.port, up.secret, up.domain)
        reader = writer = stream
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(up.host, up.port), timeout=10)
    init, enc, dec = generate_client_init(proto_tag, dc_idx, up.secret)
    writer.write(init)
    await writer.drain()
    return reader, writer, enc, dec


async def serve_via_upstream(up, proto_tag, dc_idx, clt_reader, clt_writer,
                             ctx, label) -> bool:
    """Tunnel this connection through the upstream proxy. False if it can't connect."""
    try:
        rr, rw, enc, dec = await open_upstream(up, proto_tag, dc_idx)
    except Exception as e:
        log.error(f'[{label}] upstream {up.host}:{up.port} failed: {type(e).__name__}: {e}')
        return False
    ctx.tg_enc, ctx.tg_dec = enc, dec
    log.info(f'[{label}] via upstream {up.host}:{up.port}')
    await bridge_tcp(clt_reader, clt_writer, rr, rw, ctx, label)
    return True


def create_crypto_ctx(handshake: bytes, secret: bytes, relay_init: bytes) -> CryptoCtx:
    """Create re-encryption context."""
    # Client side: key = SHA256(prekey + secret)
    clt_dec_prekey = handshake[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    clt_dec_iv = handshake[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    clt_dec_key = hashlib.sha256(clt_dec_prekey + secret).digest()

    # Client encrypt: reverse of decrypt
    clt_enc_prekey_iv = (clt_dec_prekey + clt_dec_iv)[::-1]
    clt_enc_key = hashlib.sha256(clt_enc_prekey_iv[:PREKEY_LEN] + secret).digest()
    clt_enc_iv = clt_enc_prekey_iv[PREKEY_LEN:]

    clt_dec = AesCtr(clt_dec_key, clt_dec_iv)
    clt_enc = AesCtr(clt_enc_key, clt_enc_iv)

    # Fast-forward client decryptor past 64-byte init
    clt_dec.process(b'\x00' * 64)

    # Telegram side: RAW key (no secret hash!)
    relay_enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    relay_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]

    relay_dec_prekey_iv = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    relay_dec_key = relay_dec_prekey_iv[:PREKEY_LEN]
    relay_dec_iv = relay_dec_prekey_iv[PREKEY_LEN:]

    tg_enc = AesCtr(relay_enc_key, relay_enc_iv)
    tg_dec = AesCtr(relay_dec_key, relay_dec_iv)

    # Fast-forward telegram encryptor past 64-byte init
    tg_enc.process(b'\x00' * 64)

    return CryptoCtx(clt_dec, clt_enc, tg_enc, tg_dec)


async def bridge_ws(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    ws: RawWebSocket, ctx: CryptoCtx, label: str,
                    splitter: MsgSplitter = None):
    """Bidirectional bridge: client TCP <-> Telegram WS with re-encryption."""

    async def client_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    if splitter:
                        for p in splitter.flush():
                            await ws.send(p)
                    break
                plain = ctx.clt_dec.process(data)
                encrypted = ctx.tg_enc.process(plain)
                if splitter:
                    parts = splitter.split(encrypted)
                    for p in parts:
                        await ws.send(p)
                else:
                    await ws.send(encrypted)
                log.debug(f'{label} C→WS: {len(data)}b')
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        except Exception as e:
            log.debug(f'{label} C→WS error: {e}')

    async def ws_to_client():
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                # Decrypt from Telegram, encrypt for client
                plain = ctx.tg_dec.process(data)
                encrypted = ctx.clt_enc.process(plain)
                writer.write(encrypted)
                await writer.drain()
                log.debug(f'{label} WS→C: {len(data)}b')
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        except Exception as e:
            log.debug(f'{label} WS→C error: {e}')

    tasks = [
        asyncio.create_task(client_to_ws()),
        asyncio.create_task(ws_to_client()),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except:
                pass
        try:
            await ws.close()
        except:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def bridge_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter,
                     ctx: CryptoCtx, label: str):
    """Bidirectional bridge: client TCP <-> Telegram TCP with re-encryption."""

    async def client_to_remote():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                plain = ctx.clt_dec.process(data)
                encrypted = ctx.tg_enc.process(plain)
                remote_writer.write(encrypted)
                await remote_writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        except Exception as e:
            log.debug(f'{label} C→TCP error: {e}')

    async def remote_to_client():
        try:
            while True:
                data = await remote_reader.read(65536)
                if not data:
                    break
                plain = ctx.tg_dec.process(data)
                encrypted = ctx.clt_enc.process(plain)
                writer.write(encrypted)
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        except Exception as e:
            log.debug(f'{label} TCP→C error: {e}')

    tasks = [
        asyncio.create_task(client_to_remote()),
        asyncio.create_task(remote_to_client()),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except:
                pass
        for w in (writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except:
                pass


active_tasks: set = set()


async def _read_client_init_tls(reader, writer, keys: list, label: str, client_hello: bytes = None):
    """Read TLS ClientHello and find matching key."""
    # If client_hello already provided, use it directly
    if client_hello is None:
        try:
            first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        except asyncio.IncompleteReadError:
            return None

        if first_byte[0] != TLS_HANDSHAKE:
            # Not TLS - find first masking domain for redirect
            for key in keys:
                if key.fake_tls_domain:
                    redirect = (
                        f"HTTP/1.1 301 Moved Permanently\r\n"
                        f"Location: https://{key.fake_tls_domain}/\r\n"
                        f"Content-Length: 0\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode()
                    writer.write(redirect)
                    await writer.drain()
                    return None
            return None

        try:
            hdr_rest = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        except asyncio.IncompleteReadError:
            return None

        tls_header = first_byte + hdr_rest
        record_len = struct.unpack('>H', tls_header[3:5])[0]

        try:
            record_body = await asyncio.wait_for(reader.readexactly(record_len), timeout=10)
        except asyncio.IncompleteReadError:
            return None

        client_hello = tls_header + record_body

    # Try each TLS key
    for key in keys:
        if not key.fake_tls_domain:
            continue
        tls_result = verify_client_hello(client_hello, key.secret)
        if tls_result is None:
            continue

        client_random, session_id, ts = tls_result
        log.debug(f'[{label}] Fake TLS OK (ts={ts})')

        server_hello = build_server_hello(key.secret, client_random, session_id)
        writer.write(server_hello)
        await writer.drain()

        tls_stream = FakeTlsStream(reader, writer)
        try:
            handshake = await asyncio.wait_for(tls_stream.readexactly(HANDSHAKE_LEN), timeout=10)
        except asyncio.IncompleteReadError:
            return None

        return handshake, tls_stream, tls_stream, key

    # No key matched - proxy to first masking domain
    for key in keys:
        if key.fake_tls_domain:
            log.debug(f'[{label}] Fake TLS verify failed -> masking')
            await proxy_to_masking_domain(reader, writer, client_hello, key.fake_tls_domain, label)
            return None
    return None


async def _read_client_init_plain(reader, writer, keys: list, label: str):
    """Read plain MTProto handshake and find matching key."""
    try:
        handshake = await asyncio.wait_for(reader.readexactly(HANDSHAKE_LEN), timeout=10)
    except asyncio.IncompleteReadError:
        return None

    # Try each non-TLS key
    for key in keys:
        if key.fake_tls_domain:
            continue
        result = parse_handshake(handshake, key.secret)
        if result is not None:
            return handshake, reader, writer, key

    log.warning(f'[{label}] no matching key')
    return None


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        config: Config, port: int):
    """Handle client connection."""
    task = asyncio.current_task()
    active_tasks.add(task)

    addr = writer.get_extra_info('peername')
    label = f"{addr[0]}:{addr[1]}" if addr else "?"
    log.info(f'[{label}] connected')

    keys = config.get_keys(port)
    has_tls_keys = any(k.fake_tls_domain for k in keys)
    has_plain_keys = any(not k.fake_tls_domain for k in keys)

    try:
        # Determine mode based on first byte and available keys
        first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=10)

        if first_byte[0] == TLS_HANDSHAKE and has_tls_keys:
            # TLS mode - read full ClientHello
            try:
                hdr_rest = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            except asyncio.IncompleteReadError:
                return
            tls_header = first_byte + hdr_rest
            record_len = struct.unpack('>H', tls_header[3:5])[0]
            try:
                record_body = await asyncio.wait_for(reader.readexactly(record_len), timeout=10)
            except asyncio.IncompleteReadError:
                return
            client_hello = tls_header + record_body
            log.debug(f'[{label}] TLS ClientHello: {len(client_hello)} bytes')
            init_result = await _read_client_init_tls(reader, writer, keys, label, client_hello)
        elif has_plain_keys:
            # Plain mode - read rest of handshake
            rest = await asyncio.wait_for(reader.readexactly(HANDSHAKE_LEN - 1), timeout=10)
            handshake = first_byte + rest
            # Find matching key
            matched_key = None
            for key in keys:
                if key.fake_tls_domain:
                    continue
                if parse_handshake(handshake, key.secret) is not None:
                    matched_key = key
                    break
            if matched_key:
                init_result = (handshake, reader, writer, matched_key)
            else:
                log.warning(f'[{label}] no matching key')
                init_result = None
        else:
            log.warning(f'[{label}] no suitable keys for this connection')
            init_result = None

        if init_result is None:
            return

        handshake, clt_reader, clt_writer, key = init_result

        result = parse_handshake(handshake, key.secret)
        if result is None:
            log.warning(f'[{label}] bad handshake')
            return

        dc_id, is_media, proto_tag = result
        dc_idx = -dc_id if is_media else dc_id
        media_tag = 'm' if is_media else ''
        log.info(f'[{label}] → DC{dc_id}{media_tag}')

        relay_init = generate_relay_init(proto_tag, dc_idx)
        ctx = create_crypto_ctx(handshake, key.secret, relay_init)

        # Create MsgSplitter for WS framing
        if proto_tag == PROTO_TAG_ABRIDGED:
            proto_int = PROTO_ABRIDGED_INT
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            proto_int = PROTO_INTERMEDIATE_INT
        else:
            proto_int = PROTO_PADDED_INT
        splitter = MsgSplitter(relay_init, proto_int)

        up = config.upstream
        if up and (dc_id in up.dcs or (up.media and is_media)):
            if await serve_via_upstream(up, proto_tag, dc_idx, clt_reader,
                                        clt_writer, ctx, label):
                log.info(f'[{label}] DC{dc_id}{media_tag} upstream closed')
            return

        # Get target IP and WS domains
        target_ip = config.dc_ips.get(dc_id, config.dc_ips.get(2))
        ws_domains = _ws_domains(dc_id, is_media)

        # Try pool first, then connect
        ws = await ws_pool.get(dc_id, is_media, target_ip, ws_domains)
        if ws:
            log.info(f'[{label}] WS pool hit DC{dc_id}{media_tag}')
        else:
            for domain in ws_domains:
                try:
                    ws = await RawWebSocket.connect(
                        target_ip, '/apiws', timeout=10,
                        sni=domain, http_host=domain
                    )
                    log.info(f'[{label}] WS → {target_ip} (SNI={domain})')
                    break
                except WsError as e:
                    if e.is_redirect:
                        log.debug(f'[{label}] WS {domain} redirect')
                        continue
                    log.warning(f'[{label}] WS {domain}: {e}')
                except Exception as e:
                    log.warning(f'[{label}] WS {domain} failed: {e}')

        if ws:
            await ws.send(relay_init)
            await bridge_ws(clt_reader, clt_writer, ws, ctx, label, splitter)
            log.info(f'[{label}] DC{dc_id}{media_tag} WS closed')
            return

        # WS failed: prefer the upstream tunnel over a direct TCP attempt
        if up and up.fallback:
            if await serve_via_upstream(up, proto_tag, dc_idx, clt_reader,
                                        clt_writer, ctx, label):
                log.info(f'[{label}] DC{dc_id}{media_tag} upstream closed')
                return

        # TCP fallback
        fallback_ip = config.dc_ips.get(dc_id)
        if fallback_ip:
            log.info(f'[{label}] TCP fallback → {fallback_ip}:443')
            try:
                rr, rw = await asyncio.wait_for(
                    asyncio.open_connection(fallback_ip, 443), timeout=10)
                rw.write(relay_init)
                await rw.drain()
                await bridge_tcp(clt_reader, clt_writer, rr, rw, ctx, label)
                log.info(f'[{label}] DC{dc_id}{media_tag} TCP closed')
                return
            except Exception as e:
                log.error(f'[{label}] TCP failed: {e}')

        log.error(f'[{label}] no connection to DC{dc_id}')

    except asyncio.TimeoutError:
        log.warning(f'[{label}] timeout')
    except asyncio.IncompleteReadError:
        log.debug(f'[{label}] disconnected during handshake')
    except asyncio.CancelledError:
        log.debug(f'[{label}] cancelled')
    except Exception as e:
        log.error(f'[{label}] error: {e}')
    finally:
        active_tasks.discard(task)
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass
        log.info(f'[{label}] disconnected')


async def test_connection(config: Config):
    """Test connectivity to all DCs."""
    print('Testing DC connections...')
    for dc_id in [1, 2, 3, 4, 5, 203]:
        target_ip = config.dc_ips.get(dc_id, DC_IPS.get(dc_id))
        ws_domain = f'kws{dc_id if dc_id != 203 else 2}.web.telegram.org'

        print(f'  DC {dc_id}: ', end='', flush=True)

        ws_ok = False
        try:
            ws = await RawWebSocket.connect(
                target_ip, '/apiws', timeout=5,
                sni=ws_domain, http_host=ws_domain
            )
            await ws.close()
            print(f'WS OK ({target_ip})')
            ws_ok = True
        except WsError as e:
            if e.is_redirect:
                print(f'WS 302', end='')
            else:
                print(f'WS {e.status_code}', end='')
        except Exception as e:
            print(f'WS ERR', end='')

        if not ws_ok:
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, 443), timeout=5)
                w.close()
                print(f', TCP OK')
            except:
                print(f', TCP FAIL')

    up = config.upstream
    if up:
        print(f'  Upstream {up.host}:{up.port}: ', end='', flush=True)
        try:
            if up.domain:
                st = await connect_fake_tls(up.host, up.port, up.secret, up.domain)
                st.close()
                print('OK (Fake TLS handshake verified)')
            else:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(up.host, up.port), timeout=5)
                w.close()
                print('TCP OK (dd mode, secret not verified)')
        except Exception as e:
            print(f'FAIL ({type(e).__name__}: {e})')
        print(f'  DCs routed via upstream: {sorted(up.dcs)}')
        if up.media:
            print('  Media routed via upstream: Yes (all media connections)')
    print('Done.')


async def run_server(config: Config):
    """Run proxy server."""
    ws_pool.reset()

    servers = []
    for port in config.get_ports():
        server = await asyncio.start_server(
            lambda r, w, p=port: handle_client(r, w, config, p),
            config.bind_hosts, port
        )
        servers.append(server)
        keys = config.get_keys(port)
        tls_count = sum(1 for k in keys if k.fake_tls_domain)
        plain_count = len(keys) - tls_count
        log.info(f'Listening on {config.ip}:{port} ({plain_count} dd + {tls_count} ee keys)')

    print(f'Proxy running on {len(servers)} port(s)')

    # Warmup pool
    skip = config.upstream.dcs if config.upstream else set()
    await ws_pool.warmup({dc: ip for dc, ip in config.dc_ips.items() if dc not in skip})

    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def shutdown():
        log.info('Shutting down...')
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown)

    # Start all servers
    server_tasks = []
    for server in servers:
        server_tasks.append(asyncio.create_task(server.serve_forever()))

    await stop_event.wait()

    # Stop all servers
    for server in servers:
        server.close()
    for task in active_tasks:
        task.cancel()
    if active_tasks:
        await asyncio.wait(active_tasks, timeout=5)
    for server in servers:
        await server.wait_closed()

    log.info('Server stopped')


DEFAULT_CONFIG = """\
[server]
ip = 0.0.0.0
verbose = false

[keys]
; Format: port = secret (dd-mode) or port = secret:domain (ee-mode)
; Multiple keys per port allowed
; 4242 = 12345678123456781234567812345678
; 443 = abcdefabcdefabcdefabcdefabcdefab:example.com

[datacenters]
1 = 149.154.167.220
2 = 149.154.167.220
3 = 149.154.167.220
4 = 149.154.167.220
5 = 149.154.167.220
203 = 91.105.192.100

[cloudflare]
domain =
"""


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'


def generate_config() -> tuple:
    import random
    port = random.randint(1000, 5000)
    secret = os.urandom(16).hex()
    config = f"""\
[server]
ip = 0.0.0.0
verbose = false

[keys]
{port} = {secret}

[datacenters]
1 = 149.154.167.220
2 = 149.154.167.220
3 = 149.154.167.220
4 = 149.154.167.220
5 = 149.154.167.220
203 = 91.105.192.100

[cloudflare]
domain =
"""
    return config, port, secret


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Telegram MTProto WS Proxy')
    parser.add_argument('-c', '--config', default='config.ini')
    parser.add_argument('-t', '--test', action='store_true', help='Test DC connectivity')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-l', '--link', action='store_true', help='Show connection link')
    parser.add_argument('-r', '--reset', action='store_true', help='Reset config')
    args = parser.parse_args()

    if args.reset:
        config_path = Path(args.config)
        answer = input(f'Reset {config_path}? (N/y): ').strip().lower()
        if answer == 'y':
            cfg, port, secret = generate_config()
            config_path.write_text(cfg)
            ip = get_local_ip()
            print(f'tg://proxy?server={ip}&port={port}&secret=dd{secret}')
        sys.exit(0)

    config_path = Path(args.config)
    if not config_path.exists():
        cfg, port, secret = generate_config()
        config_path.write_text(cfg)
        ip = get_local_ip()
        print(f'Created {config_path}')
        print(f'tg://proxy?server={ip}&port={port}&secret=dd{secret}')
        if not args.test:
            sys.exit(0)

    config = Config(str(config_path))

    if args.link:
        ip = get_local_ip()
        print('Connection links:')
        for port in config.get_ports():
            for key in config.get_keys(port):
                secret_hex = key.secret.hex()
                if key.fake_tls_domain:
                    domain_hex = key.fake_tls_domain.encode().hex()
                    print(f'  tg://proxy?server={ip}&port={port}&secret=ee{secret_hex}{domain_hex}')
                else:
                    print(f'  tg://proxy?server={ip}&port={port}&secret=dd{secret_hex}')
        sys.exit(0)

    level = logging.DEBUG if (args.verbose or config.verbose) else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S'
    )

    if args.test:
        asyncio.run(test_connection(config))
    else:
        asyncio.run(run_server(config))


if __name__ == '__main__':
    main()
