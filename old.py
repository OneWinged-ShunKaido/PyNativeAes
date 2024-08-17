import ctypes
from json import dumps, loads

class NativeAes:
    BCRYPT_AES_ALGORITHM = "AES"
    BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC"
    STATUS_SUCCESS = 0x00000000
    key: bytes
    iv: bytes

    def __init__(self):
        self.bcrypt = ctypes.windll.bcrypt
        self.alg_handle = None
        self.key_handle = None
        #  self.iv = b'\x00' * 16
        #  self.key = b'\x00' * 16

    def __enter__(self):
        self.alg_handle = self.open_alg_handle()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.key_handle:
            self.bcrypt.BCryptDestroyKey(self.key_handle)
        if self.alg_handle:
            self.bcrypt.BCryptCloseAlgorithmProvider(self.alg_handle, 0)

    def open_alg_handle(self):
        alg_handle = ctypes.POINTER(ctypes.c_void_p)()
        status = self.bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(alg_handle),
            ctypes.c_wchar_p(self.BCRYPT_AES_ALGORITHM),
            None,
            0
        )
        if status != self.STATUS_SUCCESS:
            raise ctypes.WinError(status)
        return alg_handle

    def generate_key(self):
        key_handle = ctypes.POINTER(ctypes.c_void_p)()
        status = self.bcrypt.BCryptGenerateSymmetricKey(
            self.alg_handle,
            ctypes.byref(key_handle),
            None,
            0,
            self.key,
            len(self.key),
            0
        )
        if status != self.STATUS_SUCCESS:
            raise ctypes.WinError(status)
        return key_handle

    def encrypt(self, plaintext: bytes) -> bytes:
        with self:
            self.key_handle = self.generate_key()
            plaintext = self.pad(plaintext, 16)

            # Convert plaintext to ctypes array
            plaintext_array = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
            ciphertext_len = len(plaintext)
            ciphertext = (ctypes.c_ubyte * ciphertext_len)()
            iv_buffer = (ctypes.c_ubyte * len(self.iv)).from_buffer_copy(self.iv)
            encrypted_size = ctypes.c_ulong(ciphertext_len)

            status = self.bcrypt.BCryptEncrypt(
                self.key_handle,
                ctypes.cast(plaintext_array, ctypes.POINTER(ctypes.c_ubyte)),
                len(plaintext),
                None,
                iv_buffer,
                len(self.iv),
                ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_ubyte)),
                ciphertext_len,
                ctypes.byref(encrypted_size),
                0
            )
            if status != self.STATUS_SUCCESS:
                raise ctypes.WinError(status)

            return bytes(ciphertext[:encrypted_size.value])

    def decrypt(self, ciphertext: bytes) -> bytes:
        with self:
            self.key_handle = self.generate_key()

            # Convert ciphertext to ctypes array
            ciphertext_array = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
            decrypted_len = len(ciphertext)
            decrypted = (ctypes.c_ubyte * decrypted_len)()
            iv_buffer = (ctypes.c_ubyte * len(self.iv)).from_buffer_copy(self.iv)
            decrypted_size = ctypes.c_ulong(decrypted_len)

            status = self.bcrypt.BCryptDecrypt(
                self.key_handle,
                ctypes.cast(ciphertext_array, ctypes.POINTER(ctypes.c_ubyte)),
                len(ciphertext),
                None,
                iv_buffer,
                len(self.iv),
                ctypes.cast(decrypted, ctypes.POINTER(ctypes.c_ubyte)),
                decrypted_len,
                ctypes.byref(decrypted_size),
                0
            )
            if status != self.STATUS_SUCCESS:
                raise ctypes.WinError(status)

            return self.unpad(bytes(decrypted[:decrypted_size.value]), 16)

    @staticmethod
    def pad(data: bytes, block_size: int = 16) -> bytes:
        padding_len = block_size - len(data) % block_size
        padding = bytes([padding_len] * padding_len)
        return data + padding

    @staticmethod
    def unpad(data: bytes, block_size: int = 16) -> bytes:
        padding_len = data[-1]
        if padding_len > block_size:
            raise ValueError("Invalid padding")
        return data[:-padding_len]
