import random
from encoder import Encoder

# Small primes used for quick trial division before Miller-Rabin testing.
# Eliminates obvious composite candidates early for faster key generation.
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
    # Pure-Python RSA implementation for key generation and basic encryption.
    # Generates primes, builds modulus/exponents, and provides encrypt/decrypt.
    # Intended for educational use and internal message key exchange.
    # Build a new RSA keypair from scratch.
    # Steps:
    # - Generate two large random primes p and q.
    # - Compute n = p*q and phi = (p-1)(q-1).
    # - Ensure e is coprime with phi so it has an inverse.
    # - Compute private exponent d = e^-1 mod phi.
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

            
        
    # Determine whether gcd(a, b) equals 1.
    # Uses the Euclidean algorithm to compute the gcd.
    # Returns True when a and b are coprime, otherwise False.
    def _is_gcd_1(self, a, b):
        a, b = a, b
        while b != 0:
            a, b = b, a % b # Euclidean algorithm where a becomes divisor and b becomes reminder till b (reminder) becomes 0 
        if a == 1:
            return True
        return False
    
    
    # Generate a random odd integer with the configured bit length.
    # Uses SystemRandom for cryptographically-strong randomness.
    # The range ensures the high bit is set for proper size.
    def _nBitRandom(self): 
        return(random.SystemRandom().randrange(2**(self._bits-1)+1, 2**self._bits-1))
     

    
    # Generate a probable prime candidate.
    # Steps:
    # - Draw a random odd candidate.
    # - Trial-divide by small primes to reject trivial composites.
    # - Run Miller-Rabin rounds to probabilistically verify primality.
    def _prime_generation(self, miller_rabin_rounds=40):
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
                
             
    
    # Perform the Miller-Rabin primality test.
    # Decomposes n-1 into 2^t * s and tests random bases.
    # Returns True if candidate is probably prime.
    def miller_rabin_test(self, candidate_prime, k=40):
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
    
    
    # Compute modular exponentiation efficiently.
    # Uses square-and-multiply to reduce complexity to O(log exponent).
    # Returns (base^exponent) mod mod.
    def _modular_exponentiation(self, base, exponent, mod):
        result = base
        bit_string = bin(exponent)[2:]  
        for bit in bit_string[1:]:  # Skip the most significant bit
            result = (result * result) % mod
            if bit == '1':
                result = (result * base) % mod
        return result

    # Compute modular inverse of a modulo b.
    # Uses Extended Euclidean Algorithm to find x where a*x ≡ 1 (mod b).
    # Returns a positive inverse in the range [0, b).
    def inv_mod(self, a, b):
        x0, x1 = 1, 0 
        orig_b = b
        while b:
            q = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - q * x1
                                            #a⋅x0+b⋅y=gcd(a,b)
                                            
        inv = x0 % orig_b  # as x0 can be negative, we take it modulo orig_b to ensure it's positive
        return inv
    
    # Encrypt plaintext bytes with RSA: c = m^e mod n.
    # Converts plaintext to an integer, validates m < n, and exponentiates.
    # Returns ciphertext bytes suitable for transmission.
    def encrypt(self, plaintext : bytes, e,n) -> bytes:
        if plaintext == 0:
            return b'\x00'
        plaintext_int = Encoder.int_from_bytes(plaintext)
        if plaintext_int >= n:
            raise ValueError("Plaintext is too long for the key size.")
        ciphertext_int = self._modular_exponentiation(plaintext_int, e, n)
        ciphertext_bytes = Encoder.int_in_bytes(ciphertext_int)
        return ciphertext_bytes
    
    # Decrypt ciphertext bytes with RSA: m = c^d mod n.
    # Converts ciphertext to an integer, exponentiates with d, and returns bytes.
    # This recovers the original plaintext when keys are valid.
    def decrypt(self, ciphertext_bytes: bytes, d: int, n: int) -> bytes:
        ciphertext_int = Encoder.int_from_bytes(ciphertext_bytes)
        plaintext_int = self._modular_exponentiation(ciphertext_int, d, n)
        plaintext_bytes = Encoder.int_in_bytes(plaintext_int)
        return plaintext_bytes

    
