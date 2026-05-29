
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# AES Inverse S-Box
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Round constants (Rcon) for key schedule
RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,0x97,
    0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,
]

class AES:
    def __init__(self, key: bytes):
        """
        Initialize AES with a raw key and precompute the key schedule.
        AES is a substitution-permutation network operating on 16-byte blocks.
        Precomputing round keys once speeds up both encryption and decryption.
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key length")
        self._key = key
        self._round_keys, self._nr = self._key_expansion(key)

    @staticmethod
    def _xtime(a: int) -> int:
        """
        Multiply a byte by x (i.e., by 2) in GF(2^8).
        Left shift performs polynomial multiplication by x; if overflow occurs,
        reduce modulo AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
        """
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff
    
    
    @staticmethod
    def _gf_mul(a: int, b: int) -> int:
        """
        Multiply two field elements in GF(2^8) using Russian-peasant multiplication.
        Repeatedly conditionally XOR the running multiplicand into the result
        based on bits of b, while advancing multiplicand with _xtime reduction.
        """
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            a = AES._xtime(a)
            b >>= 1
        return result & 0xff
    
    
    # ─────────────────────────────────────────────────────────────
    # 3. STATE HELPERS  (AES operates on a 4×4 byte matrix)
    # ─────────────────────────────────────────────────────────────
    
    @staticmethod
    def _bytes_to_state(block: bytes):
        """
        Convert linear bytes into AES state matrix (4 rows x 4 columns).
        AES defines state in column-major order; index mapping preserves that layout.
        """
        return [[block[r + 4*c] for c in range(4)] for r in range(4)]
    
    
    @staticmethod
    def _state_to_bytes(state) -> bytes:
        """
        Convert the 4x4 AES state back to linear bytes in column-major order.
        This is the inverse mapping of _bytes_to_state.
        """
        return bytes(state[r][c] for c in range(4) for r in range(4))
    
    
    # ─────────────────────────────────────────────────────────────
    # 4. AES TRANSFORMATIONS
    # ─────────────────────────────────────────────────────────────
    
    def _sub_bytes(self, state):
        """
        Apply the nonlinear S-box substitution to each state byte.
        This introduces confusion: output bits become nonlinear functions of input bits.
        """
        return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]
    
    
    def _inv_sub_bytes(self, state):
        """
        Reverse SubBytes by applying inverse S-box lookup bytewise.
        """
        return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]
    
    
    def _shift_rows(self, state):
        """
        Rotate row r left by r positions.
        This permutes byte positions across columns and enables diffusion
        when combined with MixColumns.
        """
        return [
            [state[r][(c + r) % 4] for c in range(4)]
            for r in range(4)
        ]
    
    
    def _inv_shift_rows(self, state):
        """
        Reverse ShiftRows by rotating row r right by r positions.
        """
        return [
            [state[r][(c - r) % 4] for c in range(4)]
            for r in range(4)
        ]
    
    
    @staticmethod
    def _mix_single_column(col):
        """
        Mix one column by multiplying it with a fixed matrix over GF(2^8).
        This is a linear transform that spreads each input byte influence
        across all 4 output bytes (intra-column diffusion).
        """
        a0, a1, a2, a3 = col
        return [
            AES._gf_mul(2, a0) ^ AES._gf_mul(3, a1) ^ a2             ^ a3,
            a0             ^ AES._gf_mul(2, a1) ^ AES._gf_mul(3, a2) ^ a3,
            a0             ^ a1             ^ AES._gf_mul(2, a2) ^ AES._gf_mul(3, a3),
            AES._gf_mul(3, a0) ^ a1             ^ a2             ^ AES._gf_mul(2, a3),
        ]
    
    
    @staticmethod
    def _inv_mix_single_column(col):
        """
        Apply inverse MixColumns matrix multiplication over GF(2^8).
        The constants (14,11,13,9) are entries of the inverse matrix.
        """
        a0, a1, a2, a3 = col
        return [
            AES._gf_mul(14,a0)^AES._gf_mul(11,a1)^AES._gf_mul(13,a2)^AES._gf_mul( 9,a3),
            AES._gf_mul( 9,a0)^AES._gf_mul(14,a1)^AES._gf_mul(11,a2)^AES._gf_mul(13,a3),
            AES._gf_mul(13,a0)^AES._gf_mul( 9,a1)^AES._gf_mul(14,a2)^AES._gf_mul(11,a3),
            AES._gf_mul(11,a0)^AES._gf_mul(13,a1)^AES._gf_mul( 9,a2)^AES._gf_mul(14,a3),
        ]
    
    
    def _mix_columns(self, state):
        """
        Apply _mix_single_column independently to each of the 4 state columns.
        """
        cols = [[state[r][c] for r in range(4)] for c in range(4)]
        mixed = [self._mix_single_column(col) for col in cols]
        return [[mixed[c][r] for c in range(4)] for r in range(4)]
    
    
    def _inv_mix_columns(self, state):
        """
        Apply inverse MixColumns independently to each of the 4 state columns.
        """
        cols = [[state[r][c] for r in range(4)] for c in range(4)]
        mixed = [self._inv_mix_single_column(col) for col in cols]
        return [[mixed[c][r] for c in range(4)] for r in range(4)]
    
    
    @staticmethod
    def _add_round_key(state, round_key):
        """
        Combine state with round key using XOR.
        In GF(2), XOR is both addition and subtraction, so this step is self-inverse.
        """
        return [
            [state[r][c] ^ round_key[r][c] for c in range(4)]
            for r in range(4)
        ]
    
    
    # ─────────────────────────────────────────────────────────────
    # 5. KEY EXPANSION (KEY SCHEDULE)
    # ─────────────────────────────────────────────────────────────
    
    @staticmethod
    def _key_expansion(key: bytes):
        """
        Expand the cipher key into round keys via AES key schedule recurrence.
        Core operations (RotWord, SubWord, Rcon XOR) introduce nonlinearity and
        round asymmetry so each round key is distinct but deterministically derived.
        Returns round key matrices and total round count Nr.
        """
        key_len = len(key)
        if key_len == 16:
            Nk, Nr = 4, 10
        elif key_len == 32:
            Nk, Nr = 8, 14
        else:
            raise ValueError("Key must be 16 or 32 bytes for AES-128 or AES-256.")
        W = [list(key[4*i:4*i+4]) for i in range(Nk)]
        for i in range(Nk, 4 * (Nr + 1)):
            temp = W[i - 1][:]
            if i % Nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i // Nk]
            elif Nk > 6 and i % Nk == 4:
                temp = [SBOX[b] for b in temp]
            W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])
        round_keys = []
        for rnd in range(Nr + 1):
            rk_words = W[4*rnd: 4*rnd + 4]
            state = [[rk_words[c][r] for c in range(4)] for r in range(4)]
            round_keys.append(state)
        return round_keys, Nr
    
    
    # ─────────────────────────────────────────────────────────────
    # 6. AES BLOCK CIPHER  (single 16-byte block)
    # ─────────────────────────────────────────────────────────────
    
    def aes_encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt one 16-byte block following AES round structure:
        initial AddRoundKey, then Nr-1 full rounds (SubBytes, ShiftRows, MixColumns,
        AddRoundKey), and final round without MixColumns.
        """
        state = self._bytes_to_state(block)
        state = self._add_round_key(state, self._round_keys[0])
        for rnd in range(1, self._nr + 1):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            if rnd < self._nr:
                state = self._mix_columns(state)
            state = self._add_round_key(state, self._round_keys[rnd])
        return self._state_to_bytes(state)
    
    
    def aes_decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt one 16-byte block using inverse AES transformations in reverse order.
        Round order mirrors encryption with inverse operations and reverse key order.
        """
        state = self._bytes_to_state(block)
        state = self._add_round_key(state, self._round_keys[self._nr])
        for rnd in range(self._nr - 1, -1, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self._round_keys[rnd])
            if rnd > 0:
                state = self._inv_mix_columns(state)
        return self._state_to_bytes(state)
    
    
    # ─────────────────────────────────────────────────────────────
    # 7. PKCS#7 PADDING
    # ─────────────────────────────────────────────────────────────
    
    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        """
        Add PKCS#7 padding so length becomes a multiple of block_size.
        If k bytes are needed, append k copies of value k.
        """
        n = block_size - (len(data) % block_size)
        return data + bytes([n] * n)
    
    
    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        """
        Validate and remove PKCS#7 padding.
        Strict checks prevent malformed padding from being silently accepted.
        """
        if not data:
            raise ValueError("Empty data cannot be unpadded.")
        n = data[-1]
        if n == 0 or n > 16:
            raise ValueError("Invalid PKCS#7 padding byte.")
        if data[-n:] != bytes([n] * n):
            raise ValueError("Invalid PKCS#7 padding.")
        return data[:-n]
    
    
    # ─────────────────────────────────────────────────────────────
    # 8. CBC MODE  (Cipher Block Chaining)
    # ─────────────────────────────────────────────────────────────
    
    def aes_cbc_encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypt using CBC mode: C_i = E_K(P_i XOR C_{i-1}), with C_0 = IV.
        Chaining ensures identical plaintext blocks encrypt differently if previous
        ciphertext differs, improving semantic security over ECB.
        """
        padded = self.pkcs7_pad(plaintext)
        prev = list(iv)
        ciphertext = b''
        for i in range(0, len(padded), 16):
            block = list(padded[i:i+16])
            xored = bytes([block[j] ^ prev[j] for j in range(16)])
            enc_block = self.aes_encrypt_block(xored)
            ciphertext += enc_block
            prev = list(enc_block)
        return ciphertext
    
    
    def aes_cbc_decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt CBC blocks via P_i = D_K(C_i) XOR C_{i-1}, with C_0 = IV.
        After block processing, remove PKCS#7 padding to recover original plaintext.
        """
        prev = list(iv)
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec_block = list(self.aes_decrypt_block(block))
            xored = bytes([dec_block[j] ^ prev[j] for j in range(16)])
            plaintext += xored
            prev = list(block)
        return self.pkcs7_unpad(plaintext)
    
    
    # ─────────────────────────────────────────────────────────────
    # 9. SESSION KEY GENERATION
    # ─────────────────────────────────────────────────────────────
    
    @staticmethod
    def generate_aes_key(bits: int = 256) -> bytes:
        """
        Generate a random AES key from OS entropy for 128- or 256-bit security.
        """
        if bits not in (128, 256):
            raise ValueError("AES key must be 128 or 256 bits.")
        import os
        return os.urandom(bits // 8)
    
    
    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate a random 16-byte IV (one AES block).
        In CBC mode, IV uniqueness/unpredictability is required for security.
        """
        import os
        return os.urandom(16)
    
