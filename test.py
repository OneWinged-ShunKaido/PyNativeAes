from secrets import token_bytes
from lib.PyNativeAes import NativeAes

# Initialize the AES cipher with a specific mode
native_aes = NativeAes(mode='CBC')

# Configure padding options
native_aes.PAD_ENCRYPTION_INPUT = True  # Enable padding for encryption input
native_aes.PAD_DECRYPTION_OUTPUT = False  # Disable padding for decryption output

key_encrypt = token_bytes(16)
key_decrypt = token_bytes(16)

cipher = native_aes.cipher(key=key_encrypt, iv=token_bytes(16))

plaintext = 'Hello World'
encrypted_text = cipher.encrypt(plaintext)
decrypted_text = cipher.decrypt(encrypted_text)

print(f"Decrypted text: {decrypted_text.decode()}")
