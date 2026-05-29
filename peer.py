

import signal
import sys


from encoder import Encoder
from rsa import RSA
from aes import AES


class Peer:
    # Represents a local peer with cryptographic keys and connection state.
    # Owns RSA/AES helpers and keeps track of active sockets and groups.
    # Provides convenience methods for encrypting/decrypting session data.
    # Create a peer object that owns keys and connection state.
    # Initializes RSA helper, connection dictionaries, and debug mode.
    # Generates RSA keypair immediately so the peer can handshake with others.
    def __init__(self, username, port, encoder,debug):
        self.username = username
        self.port = port
        self.public_key = None
        self.encoder = encoder
        self.connections = {}  
        self.groups = {}     
        self.rsa = RSA()
        self.aes = None
        self.debug = debug
        if self.debug:
            print("Generating Public & Private Keys...")
        self._generate_keys()
        
        if self.debug:
            print(f"Peer initialized with username: {self.username}, port: {self.port}")
            print(f"Generated Private And Public Keys are pu(e,n)={(self.public_key)} pr(d,n)={(self._private_key)}")
            
    
        
    # Initialize AES helper with a specific session key.
    # The AES instance is recreated so it always matches the active session key.
    # Debug mode prints the key in hex for inspection.
    def init_aes(self, session_key: bytes):
        if self.debug:
            print(f"Initializing AES with session key: {Encoder.represent_bytes_in_hex(session_key)}")
        self.aes = AES(session_key)
        
    # Encrypt a plaintext message using AES-CBC.
    # Steps:
    # - Create AES with the provided session key.
    # - Encrypt the plaintext with the supplied IV.
    # - Return ciphertext bytes for transmission.
    def encrypt_message(self, plaintext: bytes,session_key: bytes,iv: bytes) -> bytes:
        if self.debug:
            print(f"Encrypting message (hex) {self.encoder.decode(plaintext)} with session key: {Encoder.represent_bytes_in_hex(session_key)}")   
        self.aes = AES(session_key)
        encrypted_message = self.aes.aes_cbc_encrypt(plaintext, iv)
        if self.debug:
            print(f"Encrypted message (hex): {Encoder.represent_bytes_in_hex(encrypted_message)}")
        return encrypted_message

    
    # Decrypt a ciphertext message using AES-CBC.
    # Steps:
    # - Create AES with the provided session key.
    # - Decrypt ciphertext with the supplied IV.
    # - Return plaintext bytes for higher-level parsing.
    def decrypt_message(self, ciphertext: bytes, session_key: bytes, iv: bytes):
        if self.debug:
            print(f"Decrypting message (hex) {Encoder.represent_bytes_in_hex(ciphertext)} with session key: {Encoder.represent_bytes_in_hex(session_key)}")
        self.aes = AES(session_key)
        decrypted_message = self.aes.aes_cbc_decrypt(ciphertext, iv)
        if self.debug:
            print(f"Decrypted message (hex): {self.encoder.decode(decrypted_message)}")  
        return decrypted_message
    
    # Decrypt an RSA-encrypted session key.
    # Uses the peer's private key (d, n) to recover the raw key bytes.
    # Returns the session key ready for AES initialization.
    def decrypt_session_key(self, ciphertext : bytes):
        if self.debug:
            print(f"Decrypting session key {Encoder.represent_bytes_in_hex(ciphertext)} with private key (d,n)=({self._private_key[0]}, {self._private_key[1]})")
        decrypted_session_key = self.rsa.decrypt(ciphertext, self._private_key[0], self._private_key[1])
        if self.debug:
            print(f"Decrypted session key (hex): {Encoder.represent_bytes_in_hex(decrypted_session_key)}")
        return decrypted_session_key

    # Encrypt a session key for another peer.
    # Uses the recipient's public key (e, n) so only they can decrypt.
    # Returns ciphertext bytes to send in the handshake.
    def encrypt_session_key(self, session_key : bytes, recipient_public_key: int, recipient_n: int):
        if self.debug:
            print(f"Encrypting session key {Encoder.represent_bytes_in_hex(session_key)} for recipient with public key (e,n)=({recipient_public_key}, {recipient_n})")
        encrypted_session_key = self.rsa.encrypt(session_key, recipient_public_key, recipient_n)
        if self.debug:
            print(f"Encrypted session key (hex): {Encoder.represent_bytes_in_hex(encrypted_session_key)}")
        return encrypted_session_key

    # Generate and store RSA keypair components.
    # Public key is (e, n) and private key is (d, n).
    # These are cached on the Peer for handshakes and decryption.
    def _generate_keys(self):
        self.public_key = (self.rsa.e, self.rsa.n)
        self._private_key = (self.rsa._d, self.rsa.n)
        
    
    
    
        
        

    
    

    
    
    
        
        
