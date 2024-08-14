from secrets import token_bytes
from PyNativeAes import NativeAes
#

message = b'Hello World'
iv = b'\x00' * 16  # weak iv
key = token_bytes(16)  #  usage of secrets lib not recommend at all !!
with NativeAes() as native_aes:
  native_aes.iv = iv
  native_aes.key = key
  encrypted_message = native_aes.encrypt(message)
  decrypted_message = native_aes.decrypt(encrypted_message)

print(f'Encrypted -> {encrypted_message}')
print('Decrypted -> {decrypted_message.decode()}')
