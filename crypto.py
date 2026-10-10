"""AES-256-CTR через ctypes → OpenSSL."""
import ctypes
from ctypes import c_void_p, c_int, c_char_p, POINTER, byref, create_string_buffer

_ssl = None

def _load_ssl():
    global _ssl
    if _ssl:
        return _ssl
    for name in ('libssl.so.3', 'libssl.so.1.1', 'libssl.so', 'ssl', 'libcrypto.so.3', 'libcrypto.so.1.1', 'libcrypto.so'):
        try:
            _ssl = ctypes.CDLL(name)
            break
        except OSError:
            continue
    if not _ssl:
        raise RuntimeError('OpenSSL not found')
    _ssl.EVP_CIPHER_CTX_new.restype = c_void_p
    _ssl.EVP_aes_256_ctr.restype = c_void_p
    _ssl.EVP_EncryptInit_ex.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
    _ssl.EVP_EncryptUpdate.argtypes = [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]
    _ssl.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
    return _ssl

class AesCtr:
    """AES-256-CTR cipher."""
    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 32 or len(iv) != 16:
            raise ValueError('key must be 32 bytes, iv must be 16 bytes')
        ssl = _load_ssl()
        self._ctx = ssl.EVP_CIPHER_CTX_new()
        if not self._ctx:
            raise RuntimeError('EVP_CIPHER_CTX_new failed')
        ssl.EVP_EncryptInit_ex(self._ctx, ssl.EVP_aes_256_ctr(), None, key, iv)
        self._ssl = ssl

    def process(self, data: bytes) -> bytes:
        out = create_string_buffer(len(data) + 16)
        out_len = c_int(0)
        self._ssl.EVP_EncryptUpdate(self._ctx, out, byref(out_len), data, len(data))
        return out.raw[:out_len.value]

    def __del__(self):
        if hasattr(self, '_ctx') and self._ctx:
            self._ssl.EVP_CIPHER_CTX_free(self._ctx)
