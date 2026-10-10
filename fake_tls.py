"""Fake TLS implementation for MTProto proxy (ee-secrets).

When a client connects with an ee-secret, the traffic looks like TLS 1.3:
1. Client sends TLS ClientHello (with HMAC-signed random)
2. Server sends TLS ServerHello + CCS + fake encrypted data
3. All subsequent data wrapped in TLS Application Data records

This makes the connection look like regular HTTPS to DPI.
"""
import asyncio
import hmac
import hashlib
import os
import struct
import time
import logging

log = logging.getLogger('tg-proxy')

# TLS record types
TLS_HANDSHAKE = 0x16
TLS_CCS = 0x14        # Change Cipher Spec
TLS_APPDATA = 0x17    # Application Data

# TLS versions
TLS_VERSION_10 = b'\x03\x01'
TLS_VERSION_12 = b'\x03\x03'

# Offsets in ClientHello
CLIENT_RANDOM_OFFSET = 11
CLIENT_RANDOM_LEN = 32
SESSION_ID_OFFSET = 44
SESSION_ID_LEN = 32

# Time tolerance for timestamp validation (seconds)
TIMESTAMP_TOLERANCE = 120

# Max TLS record payload
TLS_APPDATA_MAX = 16384

# Change Cipher Spec record
CCS_FRAME = b'\x14\x03\x03\x00\x01\x01'

# ServerHello template (TLS 1.3 style)
# Format: record_header(5) + handshake_header(4) + version(2) + random(32) +
#         session_id_len(1) + session_id(32) + cipher_suite(2) + compression(1) +
#         extensions_len(2) + extensions(46)
SERVER_HELLO_TEMPLATE = bytearray(
    b'\x16\x03\x03\x00\x7a'      # TLS record: handshake, length=122
    b'\x02\x00\x00\x76'          # Handshake: ServerHello, length=118
    b'\x03\x03'                  # Version: TLS 1.2 (for compat)
    + b'\x00' * 32              # Server Random (placeholder)
    + b'\x20'                   # Session ID length: 32
    + b'\x00' * 32              # Session ID (placeholder)
    + b'\x13\x01\x00'           # Cipher suite TLS_AES_128_GCM_SHA256, no compression
    + b'\x00\x2e'               # Extensions length: 46
    + b'\x00\x33\x00\x24'       # Extension: key_share
    + b'\x00\x1d\x00\x20'       # x25519, 32 bytes
    + b'\x00' * 32              # Public key (placeholder)
    + b'\x00\x2b\x00\x02\x03\x04'  # Extension: supported_versions (TLS 1.3)
)

SH_RANDOM_OFF = 11
SH_SESSID_OFF = 44
SH_PUBKEY_OFF = 89


def verify_client_hello(data: bytes, secret: bytes) -> tuple | None:
    """Verify ClientHello with HMAC-signed random.

    The client signs the entire ClientHello (with random zeroed) using HMAC-SHA256.
    The first 28 bytes of random = first 28 bytes of HMAC.
    The last 4 bytes = timestamp XOR'd with last 4 bytes of HMAC.

    Returns (client_random, session_id, timestamp) or None if invalid.
    """
    n = len(data)
    if n < 43:
        return None

    # Must be TLS Handshake record
    if data[0] != TLS_HANDSHAKE:
        return None

    # Must be ClientHello (type 0x01)
    if data[5] != 0x01:
        return None

    # Extract client random
    client_random = bytes(data[CLIENT_RANDOM_OFFSET:CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN])

    # Zero out random for HMAC verification
    zeroed = bytearray(data)
    zeroed[CLIENT_RANDOM_OFFSET:CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] = b'\x00' * CLIENT_RANDOM_LEN

    # Calculate expected HMAC
    expected = hmac.new(secret, bytes(zeroed), hashlib.sha256).digest()

    # Verify first 28 bytes
    if not hmac.compare_digest(expected[:28], client_random[:28]):
        return None

    # Extract timestamp (XOR'd with HMAC bytes 28-31)
    ts_xor = bytes(client_random[28 + i] ^ expected[28 + i] for i in range(4))
    timestamp = struct.unpack('<I', ts_xor)[0]

    # Verify timestamp is recent
    now = int(time.time())
    if abs(now - timestamp) > TIMESTAMP_TOLERANCE:
        log.debug(f'Fake TLS: timestamp too old ({now - timestamp}s)')
        return None

    # Extract session ID
    session_id = b'\x00' * SESSION_ID_LEN
    if n >= SESSION_ID_OFFSET + SESSION_ID_LEN and data[43] == 0x20:
        session_id = bytes(data[SESSION_ID_OFFSET:SESSION_ID_OFFSET + SESSION_ID_LEN])

    return client_random, session_id, timestamp


def build_server_hello(secret: bytes, client_random: bytes, session_id: bytes) -> bytes:
    """Build ServerHello response with HMAC-signed random.

    The server random is HMAC-SHA256(secret, client_random + response_without_random).
    """
    sh = bytearray(SERVER_HELLO_TEMPLATE)

    # Fill session ID (echo back client's)
    sh[SH_SESSID_OFF:SH_SESSID_OFF + 32] = session_id

    # Fill fake public key
    sh[SH_PUBKEY_OFF:SH_PUBKEY_OFF + 32] = os.urandom(32)

    # Build CCS frame
    ccs = CCS_FRAME

    # Build fake encrypted Application Data (random size 1900-2100)
    import random
    encrypted_size = random.randint(1900, 2100)
    encrypted_data = os.urandom(encrypted_size)
    app_record = b'\x17\x03\x03' + struct.pack('>H', encrypted_size) + encrypted_data

    # Combine: ServerHello + CCS + fake encrypted data
    response = bytes(sh) + ccs + app_record

    # Calculate server random as HMAC
    hmac_input = client_random + response
    server_random = hmac.new(secret, hmac_input, hashlib.sha256).digest()

    # Insert server random
    final = bytearray(response)
    final[SH_RANDOM_OFF:SH_RANDOM_OFF + 32] = server_random

    return bytes(final)


def wrap_tls_record(data: bytes) -> bytes:
    """Wrap data in TLS Application Data record(s)."""
    parts = []
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + TLS_APPDATA_MAX]
        # Record header: type(1) + version(2) + length(2)
        parts.append(
            b'\x17\x03\x03' +  # Application Data, TLS 1.2
            struct.pack('>H', len(chunk)) +
            chunk
        )
        offset += len(chunk)
    return b''.join(parts)


class FakeTlsStream:
    """Wrapper that reads/writes TLS Application Data records.

    After TLS handshake, all data is wrapped in TLS records:
    - Outgoing: wrap in Application Data records
    - Incoming: unwrap from Application Data records
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._read_buf = bytearray()
        self._read_left = 0  # Bytes remaining in current record

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes, unwrapping TLS records."""
        while len(self._read_buf) < n:
            payload = await self._read_tls_payload()
            if not payload:
                raise asyncio.IncompleteReadError(bytes(self._read_buf), n)
            self._read_buf.extend(payload)

        result = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return result

    async def read(self, n: int) -> bytes:
        """Read up to n bytes, unwrapping TLS records."""
        if self._read_buf:
            chunk = bytes(self._read_buf[:n])
            del self._read_buf[:n]
            return chunk

        payload = await self._read_tls_payload()
        if not payload:
            return b''

        if len(payload) > n:
            self._read_buf.extend(payload[n:])
            return payload[:n]
        return payload

    async def _read_tls_payload(self) -> bytes:
        """Read one TLS record's payload."""
        # Continue reading previous record if incomplete
        if self._read_left > 0:
            data = await self._reader.read(self._read_left)
            if not data:
                return b''
            self._read_left -= len(data)
            return data

        while True:
            # Read TLS record header (5 bytes)
            hdr = await self._reader.readexactly(5)
            rtype = hdr[0]
            rec_len = struct.unpack('>H', hdr[3:5])[0]

            # Skip CCS records
            if rtype == TLS_CCS:
                if rec_len > 0:
                    await self._reader.readexactly(rec_len)
                continue

            # Only accept Application Data
            if rtype != TLS_APPDATA:
                return b''

            # Read record payload
            data = await self._reader.read(min(rec_len, 65536))
            if not data:
                return b''

            remaining = rec_len - len(data)
            if remaining > 0:
                self._read_left = remaining

            return data

    def write(self, data: bytes) -> None:
        """Write data wrapped in TLS records."""
        self._writer.write(wrap_tls_record(data))

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return self._writer.get_extra_info(name, default)


async def proxy_to_masking_domain(reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter,
                                   initial_data: bytes,
                                   domain: str, label: str) -> None:
    """Forward non-MTProto TLS connections to the masking domain.

    If someone connects without valid MTProto handshake, we act as a
    transparent proxy to the masking domain. This makes the server
    indistinguishable from a real website.
    """
    try:
        up_reader, up_writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443),
            timeout=10
        )
    except Exception as e:
        log.debug(f'[{label}] masking: cannot connect to {domain}:443: {e}')
        return

    log.debug(f'[{label}] masking -> {domain}:443')

    try:
        # Send initial data we already read
        if initial_data:
            up_writer.write(initial_data)
            await up_writer.drain()

        async def relay(src, dst):
            try:
                while True:
                    chunk = await src.read(16384)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.CancelledError):
                pass
            finally:
                try:
                    dst.close()
                    await dst.wait_closed()
                except:
                    pass

        await asyncio.gather(
            relay(reader, up_writer),
            relay(up_reader, writer),
        )
    except:
        pass
    finally:
        try:
            up_writer.close()
        except:
            pass


# ---------------------------------------------------------------------------
# Client side (used for upstream chaining: local proxy -> remote tg-proxy)
# ---------------------------------------------------------------------------

def build_client_hello(secret: bytes, domain: str, pad: bool = True) -> bytes:
    """Build a browser-like TLS ClientHello with HMAC-signed random.

    Accepted by verify_client_hello() of this project and by MTProxy/mtg
    servers that use the same ee-secret scheme.
    """
    sni = domain.encode()

    def ext(t: int, body: bytes) -> bytes:
        return struct.pack('>HH', t, len(body)) + body

    alpn_list = b'\x02h2' + b'\x08http/1.1'
    exts = b''.join([
        ext(0x0000, struct.pack('>HBH', len(sni) + 3, 0, len(sni)) + sni),   # SNI
        ext(0x0017, b''),                                                    # extended_master_secret
        ext(0xff01, b'\x00'),                                                # renegotiation_info
        ext(0x000a, struct.pack('>H', 8) + b'\x00\x1d\x00\x17\x00\x18\x00\x19'),  # groups
        ext(0x000b, b'\x01\x00'),                                            # ec_point_formats
        ext(0x0010, struct.pack('>H', len(alpn_list)) + alpn_list),          # ALPN
        ext(0x000d, struct.pack('>H', 16) +
            b'\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01'),  # sig algs
        ext(0x002b, b'\x04\x03\x04\x03\x03'),                                # supported_versions
        ext(0x002d, b'\x01\x01'),                                            # psk_key_exchange_modes
        ext(0x0033, struct.pack('>H', 36) + b'\x00\x1d\x00\x20' + os.urandom(32)),  # key_share
    ])

    ciphers = (b'\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30'
               b'\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35')

    def assemble(extensions: bytes) -> bytearray:
        body = (b'\x03\x03' + b'\x00' * 32 + b'\x20' + os.urandom(32) +
                struct.pack('>H', len(ciphers)) + ciphers + b'\x01\x00' +
                struct.pack('>H', len(extensions)) + extensions)
        hs = b'\x01' + len(body).to_bytes(3, 'big') + body
        return bytearray(b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs)

    hello = assemble(exts)
    # pad to 517 bytes like Chrome does (padding extension, type 21)
    if pad and len(hello) < 517 - 4:
        pad = 517 - len(hello) - 4
        exts += ext(0x0015, b'\x00' * pad)
        hello = assemble(exts)

    digest = hmac.new(secret, bytes(hello), hashlib.sha256).digest()
    ts = struct.pack('<I', int(time.time()))
    rnd = digest[:28] + bytes(ts[i] ^ digest[28 + i] for i in range(4))
    hello[CLIENT_RANDOM_OFFSET:CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] = rnd
    return bytes(hello)


async def connect_fake_tls(host: str, port: int, secret: bytes, domain: str,
                           timeout: float = 10.0) -> 'FakeTlsStream':
    """Open TCP, do Fake-TLS handshake as a client, return wrapped stream."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout)
    try:
        hello = build_client_hello(secret, domain)
        writer.write(hello)
        await writer.drain()

        records = b''
        for expected in (TLS_HANDSHAKE, TLS_CCS, TLS_APPDATA):
            hdr = await asyncio.wait_for(reader.readexactly(5), timeout=timeout)
            if hdr[0] != expected:
                raise ConnectionError(f'unexpected TLS record 0x{hdr[0]:02x} from upstream')
            ln = struct.unpack('>H', hdr[3:5])[0]
            body = await asyncio.wait_for(reader.readexactly(ln), timeout=timeout)
            records += hdr + body

        # Verify the server proved knowledge of the secret
        client_random = hello[CLIENT_RANDOM_OFFSET:CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]
        zeroed = bytearray(records)
        zeroed[SH_RANDOM_OFF:SH_RANDOM_OFF + 32] = b'\x00' * 32
        expected_rnd = hmac.new(secret, client_random + bytes(zeroed), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_rnd, records[SH_RANDOM_OFF:SH_RANDOM_OFF + 32]):
            raise ConnectionError('upstream ServerHello signature mismatch '
                                  '(wrong secret, or not a tg-proxy/MTProxy server)')

        writer.write(CCS_FRAME)
        await writer.drain()
        return FakeTlsStream(reader, writer)
    except BaseException:
        writer.close()
        raise
