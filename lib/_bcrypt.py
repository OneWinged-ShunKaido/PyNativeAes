import ctypes
from lib._errors import NativeAesExceptions


class BCrypt(NativeAesExceptions):
    # Class-level variables defining AES mode, algorithm, and error codes
    MODE: str
    METHOD: str
    ALGORITHM = "AES"
    DEFAULT_ALGORITHM = "AES"
    DEFAULT_MODE = "CBC"
    lib_name = "bcrypt"
    bcrypt: ctypes.WinDLL
    STATUS_SUCCESS = 0x00000000  # Status code for successful operations
    ERROR_CODES = {  # Mapping of common error codes to their descriptions
        0xC0000001: "STATUS_UNSUCCESSFUL",
        0xC000000D: "STATUS_INVALID_PARAMETER",
        0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
        # Add more relevant error codes here
    }
    AES_MODES_STR = {  # Mapping of mode strings to their corresponding Windows API names
        "CBC": "ChainingModeCBC",
        "CCM": "ChainingModeCCM",
        "CFB": "ChainingModeCFB",
        "ECB": "ChainingModeECB",
        "GCM": "ChainingModeGCM"
    }
    key_iv_pair_types = (bytes, bytearray, str)  # Supported types for keys and IVs
    key: key_iv_pair_types
    iv: key_iv_pair_types
    previous_key: bytes = None  # Cache the previous key to check for reuse
    previous_iv: bytes = None  # Cache the previous IV to check for reuse
    alg_handle = None  # Handle for the algorithm provider
    key_handle = None  # Handle for the symmetric key

    def __init__(self):
        super().__init__()
        self._load_library()  # Load the bcrypt library on initialization

    def verify_mode(self, mode: str):
        self.MODE = mode
        # Validate the mode and fall back to default if not recognized
        if self.MODE not in self.AES_MODES_STR:
            self.MODE = self.DEFAULT_MODE
        self.METHOD = self.AES_MODES_STR.get(self.MODE)

    def _load_library(self, libname: str = "bcrypt"):
        self.lib_name = libname if libname else self.lib_name
        try:
            self.bcrypt = ctypes.windll.LoadLibrary(self.lib_name)  # Load bcrypt DLL
        except OSError as e:
            print(f"Failed to load {self.lib_name}, reason: {repr(e)}")
            raise

    def open_algorithm_provider(self, algorithm: str, chaining_mode: str = None):
        # Reuse algorithm handle if key and IV haven't changed
        if (self.alg_handle is not None and
                self.previous_key == self.key and
                self.previous_iv == self.iv):
            return self.alg_handle

        # Close existing handle if key or IV has changed
        if self.alg_handle is not None:
            self.close_algorithm_provider()

        alg_handle = ctypes.POINTER(ctypes.c_void_p)()
        # Open the algorithm provider
        status = self.bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(alg_handle),
            ctypes.c_wchar_p(algorithm),
            None,
            0
        )
        if status != self.STATUS_SUCCESS:
            self.raise_win_error(status)

        # Set the chaining mode (e.g., CBC, GCM)
        if chaining_mode:
            self.set_chaining_mode(alg_handle, chaining_mode)

        self.alg_handle = alg_handle  # Cache the new algorithm handle
        self.previous_key = self.key  # Update the previous key
        self.previous_iv = self.iv  # Update the previous IV

        return alg_handle

    def close_algorithm_provider(self):
        if self.alg_handle:
            # Close the algorithm provider handle
            status = self.bcrypt.BCryptCloseAlgorithmProvider(self.alg_handle, 0)
            if status != self.STATUS_SUCCESS:
                self.raise_win_error(status)
            self.alg_handle = None  # Clear the handle

    def generate_symmetric_key(self, alg_handle, key: bytes):
        # Reuse key handle if the key hasn't changed
        if self.key_handle is not None and self.previous_key == key:
            return self.key_handle

        # Destroy existing key handle if the key has changed
        if self.key_handle is not None:
            self.destroy_key_handle()

        key_handle = ctypes.POINTER(ctypes.c_void_p)()
        # Generate a symmetric key
        status = self.bcrypt.BCryptGenerateSymmetricKey(
            alg_handle,
            ctypes.byref(key_handle),
            None,
            0,
            key,
            len(key),
            0
        )
        if status != self.STATUS_SUCCESS:
            self.raise_win_error(status)

        self.key_handle = key_handle  # Cache the new key handle
        self.previous_key = key  # Update the previous key

        return key_handle

    def destroy_key_handle(self):
        if self.key_handle:
            # Destroy the key handle
            status = self.bcrypt.BCryptDestroyKey(self.key_handle)
            if status != self.STATUS_SUCCESS:
                self.raise_win_error(status)
            self.key_handle = None  # Clear the handle

    def set_chaining_mode(self, alg_handle, chaining_mode: str):
        # Set the chaining mode property on the algorithm provider
        status = self.bcrypt.BCryptSetProperty(
            alg_handle,
            ctypes.c_wchar_p("ChainingMode"),
            ctypes.c_wchar_p(chaining_mode),
            len(chaining_mode) * 2,
            0
        )
        if status != self.STATUS_SUCCESS:
            self.raise_win_error(status)

    def bcrypt_encrypt(self, key_handle, plaintext: bytes, iv: bytes):
        ciphertext_len = len(plaintext)
        ciphertext = (ctypes.c_ubyte * ciphertext_len)()

        # Prepare the IV buffer, if applicable (not used in ECB mode)
        iv_buffer = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv) if iv and self.METHOD != "ChainingModeECB" else None
        encrypted_size = ctypes.c_ulong(ciphertext_len)

        # Perform the encryption
        status = self.bcrypt.BCryptEncrypt(
            key_handle,
            ctypes.cast((ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext), ctypes.POINTER(ctypes.c_ubyte)),
            len(plaintext),
            None,
            iv_buffer,
            len(iv) if iv_buffer else 0,
            ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_ubyte)),
            ciphertext_len,
            ctypes.byref(encrypted_size),
            0
        )
        if status != self.STATUS_SUCCESS:
            self.raise_win_error(status)

        # Handle special cases for CCM/GCM modes (returning the tag)
        if self.METHOD in ["ChainingModeCCM", "ChainingModeGCM"]:
            tag_len = 16  # Length of tag for CCM/GCM
            tag = (ctypes.c_ubyte * tag_len)()
            tag_size = ctypes.c_ulong(len(tag))
            # Retrieve the tag after encryption
            status = self.bcrypt.BCryptGetProperty(
                key_handle,
                ctypes.c_wchar_p("Tag"),
                ctypes.cast(tag, ctypes.POINTER(ctypes.c_ubyte)),
                tag_size,
                ctypes.byref(tag_size),
                0
            )
            if status != self.STATUS_SUCCESS:
                self.raise_win_error(status)
            return bytes(ciphertext[:encrypted_size.value]), bytes(tag)
        else:
            return bytes(ciphertext[:encrypted_size.value])

    def bcrypt_decrypt(self, key_handle, ciphertext: bytes, iv: bytes = None, tag: bytes = None):
        decrypted_len = len(ciphertext)
        decrypted = (ctypes.c_ubyte * decrypted_len)()

        # Prepare the IV buffer, if applicable (not used in ECB mode)
        iv_buffer = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv) if iv and self.METHOD != "ChainingModeECB" else None
        decrypted_size = ctypes.c_ulong(decrypted_len)

        # Perform the decryption
        status = self.bcrypt.BCryptDecrypt(
            key_handle,
            ctypes.cast((ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext),
                        ctypes.POINTER(ctypes.c_ubyte)),
            len(ciphertext),
            None,
            iv_buffer,
            len(iv) if iv_buffer else 0,
            ctypes.cast(decrypted, ctypes.POINTER(ctypes.c_ubyte)),
            decrypted_len,
            ctypes.byref(decrypted_size),
            0
        )
        if status != self.STATUS_SUCCESS:
            self.raise_win_error(status)

        return bytes(decrypted[:decrypted_size.value])

    def raise_win_error(self, status_code):
        # Raise a Windows error with a corresponding message
        error_message = self.ERROR_CODES.get(status_code, f"Unknown error code: {status_code}")
        raise ctypes.WinError(status_code, error_message)
