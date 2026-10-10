"""Async WebSocket client for Telegram MTProto proxy."""
import os
import ssl
import base64
import struct
import asyncio

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


class WsError(Exception):
    def __init__(self, status_code: int, message: str, location: str = None):
        self.status_code = status_code
        self.location = location
        super().__init__(f"HTTP {status_code}: {message}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


class RawWebSocket:
    """Async WebSocket client (RFC 6455)."""
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    @staticmethod
    async def connect(host: str, path: str, timeout: float = 10.0,
                      use_tls: bool = True, sni: str = None,
                      http_host: str = None) -> 'RawWebSocket':
        """Connect to WebSocket server.

        Args:
            host: hostname or IP to connect to
            path: WS path (e.g. /apiws)
            timeout: connection timeout
            use_tls: whether to use TLS
            sni: SNI hostname for TLS (defaults to host)
            http_host: Host header value (defaults to sni or host)
        """
        port = 443 if use_tls else 80
        ssl_ctx = _ssl_ctx if use_tls else None
        server_hostname = sni or host if use_tls else None
        host_header = http_host or sni or host

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx,
                                    server_hostname=server_hostname),
            timeout=timeout
        )

        # WS handshake
        ws_key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {host_header}\r\n'
            f'Upgrade: websocket\r\n'
            f'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {ws_key}\r\n'
            f'Sec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: binary\r\n'
            f'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            f'AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36\r\n'
            f'\r\n'
        )
        writer.write(req.encode())
        await writer.drain()

        # Read response
        response_lines = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b'\r\n', b'\n', b''):
                break
            response_lines.append(line.decode('utf-8', errors='replace').strip())

        if not response_lines:
            writer.close()
            raise WsError(0, 'empty response')

        first_line = response_lines[0]
        parts = first_line.split(' ', 2)
        status_code = int(parts[1]) if len(parts) >= 2 else 0

        if status_code == 101:
            return RawWebSocket(reader, writer)

        # Parse headers for redirect
        headers = {}
        for hl in response_lines[1:]:
            if ':' in hl:
                k, v = hl.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        writer.close()
        raise WsError(status_code, first_line, headers.get('location'))

    async def send(self, data: bytes):
        """Send binary data."""
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def recv(self) -> bytes | None:
        """Receive data. Returns None on close."""
        while not self._closed:
            opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                try:
                    close_frame = self._build_frame(self.OP_CLOSE,
                                                    payload[:2] if payload else b'',
                                                    mask=True)
                    self.writer.write(close_frame)
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    pong = self._build_frame(self.OP_PONG, payload, mask=True)
                    self.writer.write(pong)
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (0x1, 0x2):  # text or binary
                return payload

        return None

    async def close(self):
        """Close connection."""
        if self._closed:
            return
        self._closed = True
        try:
            close_frame = self._build_frame(self.OP_CLOSE, b'', mask=True)
            self.writer.write(close_frame)
            await self.writer.drain()
        except Exception:
            pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @staticmethod
    def _xor_mask(data: bytes, mask: bytes) -> bytes:
        if not data:
            return data
        n = len(data)
        mask_rep = (mask * (n // 4 + 1))[:n]
        return (int.from_bytes(data, 'big') ^
                int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode

        if not mask:
            if length < 126:
                return struct.pack('>BB', fb, length) + data
            if length < 65536:
                return struct.pack('>BBH', fb, 126, length) + data
            return struct.pack('>BBQ', fb, 127, length) + data

        mask_key = os.urandom(4)
        masked = RawWebSocket._xor_mask(data, mask_key)

        if length < 126:
            return struct.pack('>BB4s', fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return struct.pack('>BBH4s', fb, 0x80 | 126, length, mask_key) + masked
        return struct.pack('>BBQ4s', fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> tuple[int, bytes]:
        hdr = await self.reader.readexactly(2)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F

        if length == 126:
            length = struct.unpack('>H', await self.reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack('>Q', await self.reader.readexactly(8))[0]

        if hdr[1] & 0x80:  # masked
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return opcode, self._xor_mask(payload, mask_key)

        payload = await self.reader.readexactly(length)
        return opcode, payload
