# PyNativeAes
AES wrapper around the WIN32 API BCrypt library (https://learn.microsoft.com/fr-fr/windows/win32/api/bcrypt/)

The idea here was to combine WIN32 API & Python to make a native AES cryption tool.

Fast for very smoll data blocks (~ Kb), otherwise **very very** slow...

⚠️ Do not use this script nor secrets library to perform cryptographic operations !!

```py
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

```
![image](https://github.com/user-attachments/assets/0f1c84ad-26fe-4699-8aa4-2ee451da6388)


