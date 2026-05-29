

import signal
import sys


from encoder import Encoder
from rsa import RSA
from aes import AES


class Peer:
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
            
    
        
    def init_aes(self, session_key: bytes):
        if self.debug:
            print(f"Initializing AES with session key: {Encoder.represent_bytes_in_hex(session_key)}")
        self.aes = AES(session_key)
        
    def encrypt_message(self, plaintext: bytes,session_key: bytes,iv: bytes) -> bytes:
        if self.debug:
            print(f"Encrypting message (hex) {self.encoder.decode(plaintext)} with session key: {Encoder.represent_bytes_in_hex(session_key)}")   
        self.aes = AES(session_key)
        encrypted_message = self.aes.aes_cbc_encrypt(plaintext, iv)
        if self.debug:
            print(f"Encrypted message (hex): {Encoder.represent_bytes_in_hex(encrypted_message)}")
        return encrypted_message

    
    def decrypt_message(self, ciphertext: bytes, session_key: bytes, iv: bytes):
        if self.debug:
            print(f"Decrypting message (hex) {Encoder.represent_bytes_in_hex(ciphertext)} with session key: {Encoder.represent_bytes_in_hex(session_key)}")
        self.aes = AES(session_key)
        decrypted_message = self.aes.aes_cbc_decrypt(ciphertext, iv)
        if self.debug:
            print(f"Decrypted message (hex): {self.encoder.decode(decrypted_message)}")  
        return decrypted_message
    
    def decrypt_session_key(self, ciphertext : bytes):
        """Decrypt the session key using the peer's private key."""
        if self.debug:
            print(f"Decrypting session key {Encoder.represent_bytes_in_hex(ciphertext)} with private key (d,n)=({self._private_key[0]}, {self._private_key[1]})")
        decrypted_session_key = self.rsa.decrypt(ciphertext, self._private_key[0], self._private_key[1])
        if self.debug:
            print(f"Decrypted session key (hex): {Encoder.represent_bytes_in_hex(decrypted_session_key)}")
        return decrypted_session_key
    def encrypt_session_key(self, session_key : bytes, recipient_public_key: int, recipient_n: int):
        """Encrypt the session key using the recipient's public key."""
        if self.debug:
            print(f"Encrypting session key {Encoder.represent_bytes_in_hex(session_key)} for recipient with public key (e,n)=({recipient_public_key}, {recipient_n})")
        encrypted_session_key = self.rsa.encrypt(session_key, recipient_public_key, recipient_n)
        if self.debug:
            print(f"Encrypted session key (hex): {Encoder.represent_bytes_in_hex(encrypted_session_key)}")
        return encrypted_session_key

    def _generate_keys(self):
        self.public_key = (self.rsa.e, self.rsa.n)
        self._private_key = (self.rsa._d, self.rsa.n)
        
    
    
    
        
        

    
    

    
    
    
        
        

