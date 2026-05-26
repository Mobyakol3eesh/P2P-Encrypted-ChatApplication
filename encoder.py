


class Encoder:
    @staticmethod
    def int_in_bytes(number: int) -> bytes:
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')
    @staticmethod
    def int_from_bytes(encoded_message: bytes) -> int:
        return int.from_bytes(encoded_message, 'big')
    
