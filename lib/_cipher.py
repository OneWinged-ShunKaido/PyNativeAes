from typing import Union
from lib._bcrypt import BCrypt


class Cipher(BCrypt):
    # Flags to control padding behavior during encryption/decryption
    PAD_ENCRYPTION_INPUT: bool = True
    PAD_ENCRYPTION_OUTPUT: bool = True
    PAD_DECRYPTION_INPUT: bool = True
    PAD_DECRYPTION_OUTPUT: bool = True

    key_iv_pair_types = (bytes, bytearray, str)
    ciphertext: key_iv_pair_types

    def __init__(self):
        super().__init__()

    def set_key_iv_pair(self, key, iv):
        # In ECB mode, IV is not used, so set it to an empty byte string
        if self.METHOD == "ChainingModeECB":
            iv = b''
        # Convert key and IV to bytes if they are not already
        self.key = self._to_bytes(key)
        self.iv = self._to_bytes(iv)
        self.verify_cipher_params()  # Validate key and IV lengths and types

    def _to_bytes(self, data):
        # Ensure data is in bytes format for encryption/decryption
        if isinstance(data, str):
            return data.encode()
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        raise self.InvalidKeyTypeException(data)

    def verify_cipher_params(self):
        # Check that key and IV are of valid types and lengths
        if not isinstance(self.key, self.key_iv_pair_types):
            raise self.InvalidKeyTypeException(self.key)

        if not isinstance(self.iv, self.key_iv_pair_types):
            raise self.InvalidIvTypeException(self.iv)

        # Ensure the key length is 16 bytes (128-bit)
        if len(self.key) != 16:
            raise self.InvalidKeyLengthException(self.key)

        # Ensure the IV length is 16 bytes (if required by the mode)
        if len(self.iv) != 16 and self.METHOD != "ChainingModeECB":
            raise self.InvalidIvLengthException(self.iv)

        # Initialize algorithm and key handles for the encryption/decryption process
        self.alg_handle = self.open_algorithm_provider(algorithm=self.ALGORITHM, chaining_mode=self.METHOD)
        self.key_handle = self.generate_symmetric_key(self.alg_handle, self.key)

    def verify_ciphertext(self, ciphertext):
        # Ensure the ciphertext is in bytes and not empty
        self.ciphertext = self._to_bytes(ciphertext)
        if len(self.ciphertext) == 0:
            raise self.InvalidCipherTextTypeException(self.ciphertext)

    def encrypt(self, plaintext) -> Union[bytes, tuple]:
        plaintext_bytes = self._to_bytes(plaintext)

        # Apply padding to the input plaintext if required
        if self.PAD_ENCRYPTION_INPUT:
            plaintext_bytes = self.pad(plaintext_bytes)

        self.verify_cipher_params()

        # Encrypt and handle modes that require additional data (e.g., GCM, CCM)
        if self.METHOD in ["ChainingModeCCM", "ChainingModeGCM"]:
            ciphertext, tag = self.bcrypt_encrypt(self.key_handle, plaintext_bytes, self.iv)
            if self.PAD_ENCRYPTION_OUTPUT:
                ciphertext = self.pad(ciphertext)
            return ciphertext, tag  # Return both ciphertext and tag for these modes
        else:
            ciphertext = self.bcrypt_encrypt(self.key_handle, plaintext_bytes, self.iv)
            if self.PAD_ENCRYPTION_OUTPUT:
                ciphertext = self.pad(ciphertext)
            return ciphertext  # Return ciphertext only for other modes

    def decrypt(self, ciphertext: Union[bytes, tuple]) -> bytes:
        self.verify_cipher_params()

        # Handle decryption input depending on whether it’s a tuple (with a tag) or just bytes
        if isinstance(ciphertext, tuple):
            if len(ciphertext) == 2:
                ciphertext_bytes, tag = ciphertext
            else:
                raise ValueError("Invalid tuple format for ciphertext and tag")
        else:
            ciphertext_bytes = ciphertext
            tag = None

        # Remove padding from the input ciphertext if required
        if self.PAD_DECRYPTION_INPUT:
            ciphertext_bytes = self.unpad(ciphertext_bytes)

        # Decrypt and handle modes that use authentication tags (e.g., GCM, CCM)
        if self.METHOD in ["ChainingModeCCM", "ChainingModeGCM"]:
            if tag is None:
                raise ValueError("Tag is required for CCM and GCM modes")
            decrypted_bytes = self.bcrypt_decrypt(self.key_handle, ciphertext_bytes, self.iv, tag)
        else:
            decrypted_bytes = self.bcrypt_decrypt(self.key_handle, ciphertext_bytes, self.iv)

        # Remove padding from the output plaintext if required
        if self.PAD_DECRYPTION_OUTPUT:
            decrypted_bytes = self.unpad(decrypted_bytes)
        return decrypted_bytes

    def __del__(self):
        # Ensure resources are cleaned up when the object is destroyed
        self.cleanup_handles()

    def cleanup_handles(self):
        # Clean up key and algorithm handles to prevent memory leaks
        self.destroy_key_handle()
        self.close_algorithm_provider()

    @staticmethod
    def pad(data: bytes, block_size: int = 16) -> bytes:
        # Apply padding to make data length a multiple of block size
        padding_len = block_size - len(data) % block_size
        padding = bytes([padding_len] * padding_len)
        return data + padding

    @staticmethod
    def unpad(data: bytes, block_size: int = 16) -> bytes:
        # Remove padding and check for padding integrity
        padding_len = data[-1]
        if padding_len > block_size:
            raise ValueError("Invalid padding")
        return data[:-padding_len]
