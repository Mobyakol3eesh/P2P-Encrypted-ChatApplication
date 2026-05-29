
class Encoder:
    def __init__(self, encoding_fomat='utf-8'):
        self.encoding_format = encoding_fomat
    def encode(self, message: str) -> bytes:
        return message.encode(self.encoding_format)
    
    def decode(self, encoded_message: bytes) -> str:
        return encoded_message.decode(self.encoding_format)
    @staticmethod
    def int_in_bytes(number: int) -> bytes:
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')
    @staticmethod
    def int_from_bytes(encoded_message: bytes) -> int:
        return int.from_bytes(encoded_message, 'big')
    @staticmethod
    def represent_bytes_in_hex(message: bytes) -> str:
        return message.hex()
    @staticmethod   
    def represent_hex_in_bytes(hex_string: str) -> bytes:
        return bytes.fromhex(hex_string)