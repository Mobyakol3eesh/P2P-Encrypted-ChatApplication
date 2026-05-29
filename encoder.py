
class Encoder:
    # Initialize the encoder with a specific text encoding.
    # This encoding is reused for all encode/decode operations.
    # It allows consistent conversion between human-readable strings and bytes.
    def __init__(self, encoding_fomat='utf-8'):
        """Initialize encoder/decoder helpers with the selected text encoding."""
        self.encoding_format = encoding_fomat
    # Convert a Python string into raw bytes.
    # Uses the configured encoding to ensure consistent wire format.
    # Returns the byte sequence that can be transmitted or encrypted.
    def encode(self, message: str) -> bytes:
        """Encode a string into bytes using the configured encoding format."""
        return message.encode(self.encoding_format)
    
    # Convert bytes back into a Python string.
    # Uses the configured encoding to interpret the byte sequence.
    # This is the inverse of encode().
    def decode(self, encoded_message: bytes) -> str:
        """Decode bytes into a string using the configured encoding format."""
        return encoded_message.decode(self.encoding_format)
    # Convert an integer into big-endian bytes.
    # Used by RSA to serialize numeric plaintext/ciphertext values.
    # Length is minimal to represent the integer without leading zeros.
    @staticmethod
    def int_in_bytes(number: int) -> bytes:
        """Convert an integer to its big-endian byte representation."""
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')
    # Convert a big-endian byte sequence to an integer.
    # Used by RSA to move between byte strings and modular arithmetic.
    # This is the inverse of int_in_bytes().
    @staticmethod
    def int_from_bytes(encoded_message: bytes) -> int:
        """Convert a big-endian byte sequence into an integer."""
        return int.from_bytes(encoded_message, 'big')
    # Render raw bytes as a hexadecimal string.
    # Helpful for logging and JSON-safe transport of binary data.
    # Does not change the underlying bytes, only their representation.
    @staticmethod
    def represent_bytes_in_hex(message: bytes) -> str:
        """Return a hexadecimal string representation of raw bytes."""
        return message.hex()
    # Parse a hexadecimal string back into bytes.
    # This is used to recover raw binary from JSON-safe hex strings.
    # Inverse of represent_bytes_in_hex().
    @staticmethod   
    def represent_hex_in_bytes(hex_string: str) -> bytes:
        """Convert a hexadecimal string into raw bytes."""
        return bytes.fromhex(hex_string)