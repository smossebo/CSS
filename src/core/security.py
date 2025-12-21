# Security Module for CCS Framework
# Implements AES-256 encryption, HMAC-SHA256 verification, and key management


import hashlib
import hmac
import os
from base64 import b64encode, b64decode
from typing import Tuple, Optional, Dict, Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import argon2

class SecurityManager:
    """Manages all cryptographic operations for CCS"""
    
    # Constants from paper configuration
    AES_KEY_SIZE = 32  # 256 bits
    HMAC_KEY_SIZE = 32  # 256 bits
    SALT_SIZE = 16
    IV_SIZE = 16  # AES block size
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._setup_algorithms()
    
    def _setup_algorithms(self):
        """Setup cryptographic algorithms based on configuration"""
        # Default to AES-256-CBC as specified in paper
        self.encryption_algorithm = self.config.get(
            'encryption_algorithm', 'AES-256-CBC'
        )
        
        # Default to SHA256 as specified in paper
        self.hmac_algorithm = self.config.get('hmac_algorithm', 'SHA256')
        
        # Key derivation function
        self.kdf_algorithm = self.config.get('key_derivation', 'PBKDF2')
    
    def generate_keys(self, password: str, salt: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Generate encryption and HMAC keys from password
        Uses PBKDF2 as specified in the paper
        
        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Dictionary containing keys and salt
        """
        if salt is None:
            salt = get_random_bytes(self.SALT_SIZE)
        
        # Generate master key using PBKDF2
        if self.kdf_algorithm == 'PBKDF2':
            master_key = PBKDF2(
                password.encode(),
                salt,
                dkLen=64,  # 512 bits for both keys
                count=100000  # High iteration count for security
            )
        elif self.kdf_algorithm == 'Argon2':
            # Alternative: Argon2 for memory-hard key derivation
            argon2_hasher = argon2.PasswordHasher(
                time_cost=3, memory_cost=65536, parallelism=4
            )
            master_key = argon2_hasher.hash(password.encode()).encode()
            master_key = hashlib.sha512(master_key).digest()
        else:
            raise ValueError(f"Unsupported KDF algorithm: {self.kdf_algorithm}")
        
        # Split master key into encryption and HMAC keys
        encryption_key = master_key[:self.AES_KEY_SIZE]
        hmac_key = master_key[self.AES_KEY_SIZE:self.AES_KEY_SIZE + self.HMAC_KEY_SIZE]
        
        return {
            'encryption_key': encryption_key,
            'hmac_key': hmac_key,
            'salt': salt
        }
    
    def encrypt_message(self, plaintext: str, encryption_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt message using AES-256-CBC as specified in paper
        
        Args:
            plaintext: Message to encrypt
            encryption_key: 32-byte encryption key
            
        Returns:
            Tuple of (iv, ciphertext)
        """
        if len(encryption_key) != self.AES_KEY_SIZE:
            raise ValueError(f"Encryption key must be {self.AES_KEY_SIZE} bytes")
        
        # Generate random IV
        iv = get_random_bytes(self.IV_SIZE)
        
        # Create cipher
        if self.encryption_algorithm == 'AES-256-CBC':
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        elif self.encryption_algorithm == 'AES-256-GCM':
            cipher = AES.new(encryption_key, AES.MODE_GCM)
            iv = cipher.nonce  # GCM uses nonce instead of IV
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.encryption_algorithm}")
        
        # Encrypt
        if self.encryption_algorithm == 'AES-256-CBC':
            ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        else:  # GCM
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
            return iv, ciphertext, tag
        
        return iv, ciphertext
    
    def decrypt_message(self, iv: bytes, ciphertext: bytes, 
                       encryption_key: bytes, tag: Optional[bytes] = None) -> str:
        """
        Decrypt message using AES-256
        
        Args:
            iv: Initialization vector
            ciphertext: Encrypted message
            encryption_key: 32-byte encryption key
            tag: Authentication tag (for GCM mode)
            
        Returns:
            Decrypted plaintext
        """
        if len(encryption_key) != self.AES_KEY_SIZE:
            raise ValueError(f"Encryption key must be {self.AES_KEY_SIZE} bytes")
        
        # Create cipher
        if self.encryption_algorithm == 'AES-256-CBC':
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
        elif self.encryption_algorithm == 'AES-256-GCM':
            if tag is None:
                raise ValueError("Tag required for GCM decryption")
            cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.encryption_algorithm}")
        
        return plaintext.decode()
    
    def compute_hmac(self, data: bytes, hmac_key: bytes) -> str:
        """
        Compute HMAC-SHA256 as specified in paper (Algorithm 3)
        
        Args:
            data: Data to authenticate
            hmac_key: HMAC key
            
        Returns:
            HMAC hex digest
        """
        if self.hmac_algorithm == 'SHA256':
            return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()
        elif self.hmac_algorithm == 'SHA512':
            return hmac.new(hmac_key, data, hashlib.sha512).hexdigest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {self.hmac_algorithm}")
    
    def verify_hmac(self, data: bytes, hmac_key: bytes, expected_hmac: str) -> bool:
        """
        Verify HMAC of data
        
        Args:
            data: Data to verify
            hmac_key: HMAC key
            expected_hmac: Expected HMAC value
            
        Returns:
            True if HMAC matches, False otherwise
        """
        computed_hmac = self.compute_hmac(data, hmac_key)
        return hmac.compare_digest(computed_hmac, expected_hmac)
    
    def encrypt_and_sign(self, plaintext: str, keys: Dict) -> Dict:
        """
        Encrypt message and compute HMAC for integrity
        
        Args:
            plaintext: Message to protect
            keys: Dictionary with encryption_key and hmac_key
            
        Returns:
            Dictionary with encrypted data and HMAC
        """
        # Encrypt
        if self.encryption_algorithm == 'AES-256-CBC':
            iv, ciphertext = self.encrypt_message(plaintext, keys['encryption_key'])
        else:  # GCM
            iv, ciphertext, tag = self.encrypt_message(plaintext, keys['encryption_key'])
        
        # Compute HMAC of ciphertext
        hmac_value = self.compute_hmac(ciphertext, keys['hmac_key'])
        
        result = {
            'iv': b64encode(iv).decode(),
            'ciphertext': b64encode(ciphertext).decode(),
            'hmac': hmac_value,
            'algorithm': self.encryption_algorithm
        }
        
        if self.encryption_algorithm == 'AES-256-GCM':
            result['tag'] = b64encode(tag).decode()
        
        return result
    
    def decrypt_and_verify(self, encrypted_data: Dict, keys: Dict) -> str:
        """
        Decrypt message and verify HMAC
        
        Args:
            encrypted_data: Dictionary with encrypted data
            keys: Dictionary with encryption_key and hmac_key
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If HMAC verification fails
        """
        # Decode from base64
        iv = b64decode(encrypted_data['iv'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        
        # Verify HMAC
        if not self.verify_hmac(ciphertext, keys['hmac_key'], encrypted_data['hmac']):
            raise ValueError("HMAC verification failed - data may be tampered")
        
        # Decrypt
        if encrypted_data['algorithm'] == 'AES-256-CBC':
            plaintext = self.decrypt_message(iv, ciphertext, keys['encryption_key'])
        else:  # GCM
            tag = b64decode(encrypted_data['tag'])
            plaintext = self.decrypt_message(iv, ciphertext, keys['encryption_key'], tag)
        
        return plaintext
    
    def secure_file_hash(self, file_path: str, key: bytes) -> str:
        """
        Compute secure hash of file content using HMAC
        Used for file matching in extraction (Algorithm 3)
        
        Args:
            file_path: Path to file
            key: HMAC key
            
        Returns:
            Secure hash of file content
        """
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks for large files
                hasher = hmac.new(key, b'', getattr(hashlib, self.hmac_algorithm.lower()))
                
                chunk_size = 8192  # 8KB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
                
                return hasher.hexdigest()
        except Exception as e:
            raise IOError(f"Error reading file {file_path}: {e}")
    
    def create_protocol_signature(self, protocol: Dict, key: bytes) -> str:
        """
        Create cryptographic signature for protocol configuration
        Ensures protocol integrity
        
        Args:
            protocol: Protocol dictionary
            key: Signature key
            
        Returns:
            Protocol signature
        """
        # Convert protocol to canonical string
        protocol_str = json.dumps(protocol, sort_keys=True)
        return self.compute_hmac(protocol_str.encode(), key)


class KeyManager:
    """Manages key lifecycle and storage"""
    
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.key_cache = {}
    
    def load_keys_from_password(self, password: str, 
                               salt_file: Optional[str] = None) -> Dict:
        """
        Load or generate keys from password
        
        Args:
            password: User password
            salt_file: Optional file containing salt
            
        Returns:
            Dictionary with keys
        """
        cache_key = f"password:{password}:{salt_file}"
        
        if cache_key in self.key_cache:
            return self.key_cache[cache_key]
        
        # Load or generate salt
        if salt_file and os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = None
        
        # Generate keys
        keys = self.security_manager.generate_keys(password, salt)
        
        # Save salt if new
        if salt_file and salt is None:
            with open(salt_file, 'wb') as f:
                f.write(keys['salt'])
        
        self.key_cache[cache_key] = keys
        return keys
    
    def rotate_keys(self, old_keys: Dict, new_password: str) -> Dict:
        """
        Rotate keys to new password
        
        Args:
            old_keys: Old keys dictionary
            new_password: New password
            
        Returns:
            New keys dictionary
        """
        # Generate new keys from new password
        new_keys = self.security_manager.generate_keys(new_password)
        
        # TODO: In production, would need to re-encrypt existing data
        
        return new_keys
    
    def clear_cache(self):
        """Clear key cache"""
        self.key_cache.clear()


# Utility functions
def generate_random_key(length: int = 32) -> bytes:
    """Generate cryptographically secure random key"""
    return get_random_bytes(length)

def derive_key_from_seed(seed: str, salt: bytes = None, length: int = 32) -> bytes:
    """Derive key from seed using PBKDF2"""
    if salt is None:
        salt = get_random_bytes(16)
    
    return PBKDF2(seed.encode(), salt, dkLen=length, count=100000)
