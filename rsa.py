import random
from encoder import Encoder

class RSA:
    
    def __init__(self, p=11, q=13, e=65537): # standard public exponent (e)
        self._p = p
        self._q = q
        self.n = self._p * self._q  
        self._phi_n = (self._p - 1) * (self._q - 1)
        self.e = e
        if self._is_gcd_1(self.e, self._phi_n) == False:
            raise ValueError("e must be coprime to φ(n).")
        self._d = self.inv_mod(self.e, self._phi_n)  # private exponent d = e^-1 mod φ(n)
    
    def _is_gcd_1(self, a, b):
        a, b = a, b
        while b != 0:
            a, b = b, a % b # Euclidean algorithm where a becomes divisor and b becomes reminder till b (reminder) becomes 0 
        if a == 1:
            return True
        return False
     
    
    def _modular_exponentiation(self, base, exponent, mod):
        """Efficiently compute (base^exponent) % mod. Using Fast Modular Exponentiation by Squaring."""
        result = base
        bit_string = bin(exponent)[2:]  
        for bit in bit_string[1:]:  # Skip the most significant bit
            result = (result * result) % mod
            if bit == '1':
                result = (result * base) % mod
        return result

    def inv_mod(self, a, b):
        """Compute modular inverse of a mod m using Extended Euclidean Algorithm."""
        x0, x1 = 1, 0 
        orig_b = b
        while b:
            q = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - q * x1
                                            #a⋅x0+b⋅y=gcd(a,b)
                                            
        inv = x0 % orig_b  # as x0 can be negative, we take it modulo orig_b to ensure it's positive
        return inv
    
    def encrypt(self, plaintext : bytes, e,n) -> bytes:
        """Encrypt plaintext using the public key (n, e)."""
        if plaintext == 0:
            return b'\x00'
        plaintext_int = Encoder.int_from_bytes(plaintext)
        if plaintext_int >= n:
            raise ValueError("Plaintext is too long for the key size.")
        ciphertext_int = self._modular_exponentiation(plaintext_int, e, n)
        ciphertext_bytes = Encoder.int_in_bytes(ciphertext_int)
        return ciphertext_bytes
    
    def decrypt(self, ciphertext_bytes: bytes, d: int, n: int) -> bytes:
        """Decrypt ciphertext using the private key (n, d)."""
        ciphertext_int = Encoder.int_from_bytes(ciphertext_bytes)
        plaintext_int = self._modular_exponentiation(ciphertext_int, d, n)
        plaintext_bytes = Encoder.int_in_bytes(plaintext_int)
        return plaintext_bytes

    
