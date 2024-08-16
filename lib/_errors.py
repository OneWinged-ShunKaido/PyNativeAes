class NativeAesExceptions:

    def __init__(self):
        super().__init__()

    class InvalidModeException(Exception):

        def __init__(self, mode: str, message: str = "Invalid or not supported \"{}\" mode"):
            self.message = message.format(mode)
            super().__init__(self.message)

    class InvalidKeyTypeException(Exception):

        def __init__(self, key, message: str = "Invalid type {} for key {}"):
            self.message = message.format(type(key), key)
            super().__init__(self.message)

    class InvalidKeyLengthException(Exception):

        def __init__(self, key, message: str = "Invalid length for key {} "):
            self.message = message.format(key)
            super().__init__(self.message)

    class InvalidIvTypeException(Exception):

        def __init__(self, iv, message: str = "Invalid type {} for iv {}"):
            self.message = message.format(type(iv), iv)
            super().__init__(self.message)

    class InvalidIvLengthException(Exception):

        def __init__(self, iv, message: str = "Invalid length for iv {} "):
            self.message = message.format(iv)
            super().__init__(self.message)

    class InvalidCipherTextTypeException(Exception):

        def __init__(self, t_message, message: str = "Invalid type {} for ciphertext"):
            self.message = message.format(type(t_message))
            super().__init__(self.message)