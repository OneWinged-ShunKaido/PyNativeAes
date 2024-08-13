# PyNativeAes
AES wrapper around the WIN32 API BCrypt library

The idea here was to combine WIN32 API & Python to make a native AES cryption tool.

Fast for very smoll data blocks (~ Kb), otherwise **very very** slow...

```py
from secrets import token_bytes
from PyNativeAes import NativeAes
#

message = b'Hello World'
iv = b'\x00' * 16
key = token_bytes(16)
with NativeAes() as native_aes:
  self.iv = iv
  self.key = key
  encrypted_message = native_aes.encrypt(message)
  decrypted_message = native_aes.decrypt(encrypted_message)

print(f'Encrypted -> {encrypted_message}')
print('Decrypted -> {decrypted_message.decode()}')
```
  


