import random
from encoder import Encoder

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

class RSA:
    
    def __init__(self, bits=1024, e=65537, miller_rabin_rounds=40): # standard public exponent (e)
        self._bits = bits
        self._p = None
        self._q = None
        self._phi_n = None
        self.e = e
        while True:
            p = self._prime_generation(miller_rabin_rounds)
            q = self._prime_generation(miller_rabin_rounds)
            if p == q:
                continue
            phi = (p-1)*(q-1)
            if self._is_gcd_1(self.e, phi):
                self._p = p
                self._q = q
                self._phi_n = phi
                break
        self.n = self._p * self._q  
        self._d = self.inv_mod(self.e, self._phi_n)  # private exponent d = e^-1 mod φ(n)

            
        
    def _is_gcd_1(self, a, b):
        a, b = a, b
        while b != 0:
            a, b = b, a % b # Euclidean algorithm where a becomes divisor and b becomes reminder till b (reminder) becomes 0 
        if a == 1:
            return True
        return False
    
    
    def _nBitRandom(self): 
  
        return(random.SystemRandom().randrange(2**(self._bits-1)+1, 2**self._bits-1))
     

    
    def _prime_generation(self, miller_rabin_rounds=40):
        '''Generate a prime candidate divisible 
        by first primes'''
        while True:
        # Obtain a random number
            candidate_prime = self._nBitRandom()

            # Test divisibility by pre-generated
            # primes
            for divisor in SMALL_PRIMES:
                if candidate_prime % divisor == 0 and divisor**2 <= candidate_prime:
                    break
            else:
                # If candidate is not divisible by any of the small primes, test it with Miller-Rabin
                if self.miller_rabin_test(candidate_prime, k=miller_rabin_rounds):
                    return candidate_prime
                
             
    
    def miller_rabin_test(self, candidate_prime, k=40):
        """Miller-Rabin primality test.
            candidate_prime : number to test
            k : number of rounds
            """
        s = candidate_prime - 1
        t = 0
        while s % 2 == 0:
            # keep halving s while it is even (and use t
            # to count how many times we halve s)
            s = s // 2
            t += 1

        for _ in range(k): 
            a = random.randrange(2, candidate_prime - 1)
            v = self._modular_exponentiation(a, s, candidate_prime)
            if v != 1: # this test does not apply if v is 1.
                i = 0
                while v != (candidate_prime - 1):
                    if i == t - 1:
                        return False
                    else:
                        i = i + 1
                        v = (v ** 2) % candidate_prime
        return True
    
    
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

    
