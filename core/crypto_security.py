import os
import base64
import hashlib
import secrets
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import jwt

logger = logging.getLogger('core')

class CryptoSecurity:
    """
    Advanced cryptographic security module providing secure encryption, hashing,
    and key management capabilities for protecting sensitive data.
    """
    
    def __init__(self):
        """Initialize the cryptographic security module."""
        self.key_store = {}
        self.token_secret = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
        self.salt = os.environ.get('CRYPTO_SALT', secrets.token_bytes(16))
    
    def generate_key(self, key_size=256):
        """
        Generate a cryptographically secure random key.
        
        Args:
            key_size: Size of the key in bits (default: 256)
            
        Returns:
            Random key as bytes
        """
        if key_size % 8 != 0:
            raise ValueError("Key size must be a multiple of 8 bits")
            
        return secrets.token_bytes(key_size // 8)
    
    def derive_key(self, password, salt=None, iterations=100000):
        """
        Derive a key from a password using PBKDF2.
        
        Args:
            password: Password to derive key from
            salt: Salt for key derivation (default: use instance salt)
            iterations: Number of iterations for PBKDF2
            
        Returns:
            Derived key as bytes
        """
        if salt is None:
            salt = self.salt
            
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        
        return kdf.derive(password)
    
    def encrypt_aes_gcm(self, plaintext, key=None):
        """
        Encrypt data using AES-GCM mode.
        
        Args:
            plaintext: Data to encrypt (str or bytes)
            key: Encryption key (default: generate new key)
            
        Returns:
            Dictionary containing encrypted data, nonce, and tag
        """
        if key is None:
            key = self.generate_key()
            
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Generate a random nonce
        nonce = os.urandom(12)
        
        # Create an encryptor
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce)
        ).encryptor()
        
        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8')
        }
    
    def decrypt_aes_gcm(self, ciphertext, nonce, tag, key):
        """
        Decrypt data encrypted with AES-GCM mode.
        
        Args:
            ciphertext: Encrypted data as string or bytes
            nonce: Nonce used for encryption
            tag: Authentication tag
            key: Decryption key
            
        Returns:
            Decrypted data as bytes
        """
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
            
        if isinstance(nonce, str):
            nonce = base64.b64decode(nonce)
            
        if isinstance(tag, str):
            tag = base64.b64decode(tag)
            
        if isinstance(key, str):
            key = base64.b64decode(key)
            
        # Create a decryptor
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag)
        ).decryptor()
        
        # Decrypt the ciphertext
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def generate_rsa_keypair(self, key_size=2048):
        """
        Generate an RSA key pair.
        
        Args:
            key_size: Size of the key in bits (default: 2048)
            
        Returns:
            Dictionary containing private and public keys in PEM format
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return {
            'private_key': private_pem,
            'public_key': public_pem
        }
    
    def rsa_encrypt(self, plaintext, public_key_pem):
        """
        Encrypt data using RSA OAEP.
        
        Args:
            plaintext: Data to encrypt (str or bytes)
            public_key_pem: Public key in PEM format
            
        Returns:
            Encrypted data as base64 string
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode('utf-8')
            
        public_key = load_pem_public_key(public_key_pem)
        
        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def rsa_decrypt(self, ciphertext, private_key_pem):
        """
        Decrypt data encrypted with RSA OAEP.
        
        Args:
            ciphertext: Encrypted data as string or bytes
            private_key_pem: Private key in PEM format
            
        Returns:
            Decrypted data as bytes
        """
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
            
        if isinstance(private_key_pem, str):
            private_key_pem = private_key_pem.encode('utf-8')
            
        private_key = load_pem_private_key(
            private_key_pem,
            password=None
        )
        
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    def generate_token(self, payload, expiration_hours=24):
        """
        Generate a JWT token.
        
        Args:
            payload: Dictionary containing token claims
            expiration_hours: Token expiration time in hours
            
        Returns:
            JWT token as string
        """
        expiration = datetime.utcnow() + timedelta(hours=expiration_hours)
        payload['exp'] = expiration
        
        return jwt.encode(payload, self.token_secret, algorithm='HS256')
    
    def verify_token(self, token):
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            return jwt.decode(token, self.token_secret, algorithms=['HS256'])
        except jwt.PyJWTError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
    
    def secure_hash(self, data, algorithm='sha256'):
        """
        Create a secure hash of data.
        
        Args:
            data: Data to hash (str or bytes)
            algorithm: Hash algorithm to use
            
        Returns:
            Hash digest as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha384':
            return hashlib.sha384(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        elif algorithm == 'blake2b':
            return hashlib.blake2b(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    def create_hmac(self, data, key=None):
        """
        Create an HMAC for data authentication.
        
        Args:
            data: Data to authenticate (str or bytes)
            key: Key for HMAC (default: generate new key)
            
        Returns:
            Dictionary with HMAC digest and key
        """
        if key is None:
            key = self.generate_key()
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        digest = h.finalize()
        
        return {
            'hmac': base64.b64encode(digest).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8')
        }
    
    def verify_hmac(self, data, hmac_digest, key):
        """
        Verify an HMAC for data authentication.
        
        Args:
            data: Data to verify (str or bytes)
            hmac_digest: HMAC digest to verify against
            key: Key used for HMAC
            
        Returns:
            True if HMAC is valid, False otherwise
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if isinstance(hmac_digest, str):
            hmac_digest = base64.b64decode(hmac_digest)
            
        if isinstance(key, str):
            key = base64.b64decode(key)
            
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        
        try:
            h.verify(hmac_digest)
            return True
        except Exception:
            return False
    
    def secure_random_string(self, length=32):
        """
        Generate a cryptographically secure random string.
        
        Args:
            length: Length of the random string
            
        Returns:
            Random string
        """
        # Generate random bytes
        random_bytes = secrets.token_bytes(length)
        
        # Convert to URL-safe base64 and remove padding
        random_string = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        
        # Trim to requested length
        return random_string[:length]
    
    def encrypt_with_fernet(self, data, key=None):
        """
        Encrypt data using Fernet (AES-128-CBC + HMAC).
        
        Args:
            data: Data to encrypt (str or bytes)
            key: Fernet key (default: generate new key)
            
        Returns:
            Dictionary with encrypted data and key
        """
        if key is None:
            key = Fernet.generate_key()
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        f = Fernet(key)
        token = f.encrypt(data)
        
        return {
            'token': token.decode('utf-8'),
            'key': key.decode('utf-8') if isinstance(key, bytes) else key
        }
    
    def decrypt_with_fernet(self, token, key):
        """
        Decrypt data encrypted with Fernet.
        
        Args:
            token: Encrypted token
            key: Fernet key
            
        Returns:
            Decrypted data
        """
        if isinstance(token, str):
            token = token.encode('utf-8')
            
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        f = Fernet(key)
        return f.decrypt(token)
        
    def store_key(self, key_id, key, metadata=None):
        """
        Store a key in the key store.
        
        Args:
            key_id: Identifier for the key
            key: Key to store
            metadata: Additional metadata for the key
            
        Returns:
            True if successful
        """
        if not metadata:
            metadata = {}
            
        self.key_store[key_id] = {
            'key': key,
            'created_at': datetime.utcnow().isoformat(),
            **metadata
        }
        
        return True
    
    def get_key(self, key_id):
        """
        Retrieve a key from the key store.
        
        Args:
            key_id: Identifier for the key
            
        Returns:
            Key data or None if not found
        """
        return self.key_store.get(key_id) 