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
        """
        Build an RSA keypair from scratch.
        Steps:
        1) generate two random large primes p and q,
        2) compute n = p*q and phi(n) = (p-1)(q-1),
        3) ensure gcd(e, phi(n)) = 1 so e is invertible mod phi(n),
        4) compute d = e^(-1) mod phi(n).
        The pair (e, n) is public and (d, n) is private.
        """
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
        """
        Check coprimality using the Euclidean algorithm.
        Repeatedly apply gcd(a, b) = gcd(b, a mod b) until the remainder is zero.
        If the final non-zero divisor is 1, then a and b are coprime.
        """
        a, b = a, b
        while b != 0:
            a, b = b, a % b # Euclidean algorithm where a becomes divisor and b becomes reminder till b (reminder) becomes 0 
        if a == 1:
            return True
        return False
    
    
    def _nBitRandom(self): 
        """
        Generate a random odd-range integer with roughly _bits bits.
        SystemRandom uses OS entropy, which is appropriate for key generation.
        The numeric interval is chosen to keep candidates in the high bit-length range.
        """
  
        return(random.SystemRandom().randrange(2**(self._bits-1)+1, 2**self._bits-1))
     

    
    def _prime_generation(self, miller_rabin_rounds=40):
        """
        Generate a probable prime in two phases:
        1) quick trial division against small primes to reject obvious composites,
        2) probabilistic Miller-Rabin rounds for strong compositeness detection.
        This hybrid approach is much faster than running Miller-Rabin on every candidate.
        """
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
        """
        Probabilistic primality test based on modular arithmetic witnesses.
        Write candidate_prime - 1 as (2^t) * s with s odd, then test random bases a.
        If a^s mod n is neither 1 nor -1, repeated squaring should eventually hit -1
        for primes; failing that indicates compositeness.
        Passing k rounds means "probably prime" with very low error probability.
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
        """
        Compute (base^exponent) mod mod via square-and-multiply.
        Instead of multiplying base exponent times, process exponent bits:
        each step squares the current value, and multiplies by base only for '1' bits.
        This reduces complexity from O(exponent) multiplications to O(log exponent).
        """
        result = base
        bit_string = bin(exponent)[2:]  
        for bit in bit_string[1:]:  # Skip the most significant bit
            result = (result * result) % mod
            if bit == '1':
                result = (result * base) % mod
        return result

    def inv_mod(self, a, b):
        """
        Compute modular inverse using Extended Euclidean Algorithm.
        The algorithm finds coefficients x,y such that a*x + b*y = gcd(a,b).
        When gcd(a,b)=1, x is the inverse of a modulo b, so a*x ≡ 1 (mod b).
        """
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
        """
        Perform textbook RSA encryption: c = m^e mod n.
        The plaintext bytes are interpreted as a big-endian integer m.
        Validity requires m < n; otherwise modular reduction would corrupt data.
        """
        if plaintext == 0:
            return b'\x00'
        plaintext_int = Encoder.int_from_bytes(plaintext)
        if plaintext_int >= n:
            raise ValueError("Plaintext is too long for the key size.")
        ciphertext_int = self._modular_exponentiation(plaintext_int, e, n)
        ciphertext_bytes = Encoder.int_in_bytes(ciphertext_int)
        return ciphertext_bytes
    
    def decrypt(self, ciphertext_bytes: bytes, d: int, n: int) -> bytes:
        """
        Perform textbook RSA decryption: m = c^d mod n.
        By RSA arithmetic, (m^e)^d mod n recovers m when keys are valid.
        The result integer is converted back to bytes for application use.
        """
        ciphertext_int = Encoder.int_from_bytes(ciphertext_bytes)
        plaintext_int = self._modular_exponentiation(ciphertext_int, d, n)
        plaintext_bytes = Encoder.int_in_bytes(plaintext_int)
        return plaintext_bytes

    
