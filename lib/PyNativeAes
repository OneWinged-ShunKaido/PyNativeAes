from lib._cipher import Cipher


class NativeAes(Cipher):
    #   MODE: Union[CBCMode, CCMMode, CFBMode, ECBMode, GCMMode] = CBCMode

    def __init__(self, mode: str = "CBC"):
        super().__init__()
        self.verify_mode(mode.upper())

    def cipher(self, key, iv=b'\x00' * 16):
        self.set_key_iv_pair(key=key, iv=iv)

        return self

