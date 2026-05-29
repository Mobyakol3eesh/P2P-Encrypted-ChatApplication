
class Encoder:
    # Provide consistent text/binary conversion helpers for the entire app.
    # Centralizes UTF-8 encoding and decoding so wire format is predictable.
    # Also includes integer/hex helpers used by RSA and JSON transport.
    # Initialize the encoder with a specific text encoding.
    # This encoding is reused for all encode/decode operations.
    # It allows consistent conversion between human-readable strings and bytes.
    def __init__(self, encoding_fomat='utf-8'):
        self.encoding_format = encoding_fomat

    # Convert a Python string into raw bytes for transport or encryption.
    # Uses the configured encoding to ensure a consistent wire format.
    # Returns the byte sequence that can be transmitted or encrypted.
    def encode(self, message: str) -> bytes:
        return message.encode(self.encoding_format)
    
    # Convert raw bytes back into a Python string.
    # Uses the configured encoding to interpret the byte sequence.
    # This is the inverse of encode() for user-visible text.
    def decode(self, encoded_message: bytes) -> str:
        return encoded_message.decode(self.encoding_format)

    # Convert an integer into a minimal big-endian byte sequence.
    # Used by RSA to serialize numeric plaintext/ciphertext values.
    # Avoids leading zeros while preserving the integer value.
    @staticmethod
    def int_in_bytes(number: int) -> bytes:
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')

    # Convert a big-endian byte sequence back into an integer.
    # Used by RSA to recover numeric values from ciphertext/plaintext bytes.
    # This is the inverse of int_in_bytes().
    @staticmethod
    def int_from_bytes(encoded_message: bytes) -> int:
        return int.from_bytes(encoded_message, 'big')

    # Render raw bytes as a hexadecimal string for logging/JSON safety.
    # Helpful when binary data must be printed or embedded in JSON payloads.
    # Does not change the underlying bytes, only their representation.
    @staticmethod
    def represent_bytes_in_hex(message: bytes) -> str:
        return message.hex()

    # Parse a hexadecimal string back into raw bytes.
    # Used to recover binary values sent as hex strings in JSON payloads.
    # Inverse of represent_bytes_in_hex().
    @staticmethod   
    def represent_hex_in_bytes(hex_string: str) -> bytes:
        return bytes.fromhex(hex_string)