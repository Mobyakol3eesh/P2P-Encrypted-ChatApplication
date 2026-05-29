
class Encoder:
    def __init__(self, encoding_fomat='utf-8'):
        """Initialize encoder/decoder helpers with the selected text encoding."""
        self.encoding_format = encoding_fomat
    def encode(self, message: str) -> bytes:
        """Encode a string into bytes using the configured encoding format."""
        return message.encode(self.encoding_format)
    
    def decode(self, encoded_message: bytes) -> str:
        """Decode bytes into a string using the configured encoding format."""
        return encoded_message.decode(self.encoding_format)
    @staticmethod
    def int_in_bytes(number: int) -> bytes:
        """Convert an integer to its big-endian byte representation."""
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')
    @staticmethod
    def int_from_bytes(encoded_message: bytes) -> int:
        """Convert a big-endian byte sequence into an integer."""
        return int.from_bytes(encoded_message, 'big')
    @staticmethod
    def represent_bytes_in_hex(message: bytes) -> str:
        """Return a hexadecimal string representation of raw bytes."""
        return message.hex()
    @staticmethod   
    def represent_hex_in_bytes(hex_string: str) -> bytes:
        """Convert a hexadecimal string into raw bytes."""
        return bytes.fromhex(hex_string)