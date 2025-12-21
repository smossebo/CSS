import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from typing import List, Dict, Optional
import logging
import time
from collections import defaultdict

class CCSExtractor:
    """Optimized CCS Extraction with Precomputed Hash Maps (Algorithm 2, 3, 8)"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.hash_maps = {}  # Cache for precomputed hash maps
        
    def compute_hmac(self, file_content: bytes, key: bytes) -> str:
        """Compute HMAC-SHA256 for file content (Algorithm 3)"""
        return hmac.new(key, file_content, hashlib.sha256).hexdigest()
    
    def precompute_hash_maps(self, cover_folders: List[str], 
                            protocol: Dict, encryption_key: bytes) -> Dict:
        """
        Precomputation Phase (Optimized Extraction)
        One-time per session computation
        """
        hash_maps = {}
        
        for i, folder in enumerate(cover_folders):
            if not os.path.exists(folder):
                self.logger.warning(f"Cover folder {folder} does not exist")
                continue
                
            files = [os.path.join(folder, f) for f in os.listdir(folder) 
                    if os.path.isfile(os.path.join(folder, f))]
            
            # Apply protocol to sort files
            from .embedding import CCSEmbedder
            embedder = CCSEmbedder(self.config)
            sorted_files = embedder.apply_protocol(files, protocol)
            
            # Create hash map for quick lookup
            folder_map = {}
            for idx, file_path in enumerate(sorted_files):
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        file_hash = self.compute_hmac(content, encryption_key)
                        folder_map[file_hash] = idx
                except Exception as e:
                    self.logger.error(f"Error reading file {file_path}: {e}")
                    continue
            
            hash_maps[folder] = {
                'sorted_files': sorted_files,
                'hash_map': folder_map,
                'file_count': len(sorted_files)
            }
        
        return hash_maps
    
    def extract(self, stego_folder: str, cover_folders: List[str], 
               stego_key: Dict, max_attempts: int = 3) -> Optional[str]:
        """
        Enterprise-Grade Fault Tolerant Extraction (Algorithm 8)
        
        Args:
            stego_folder: Path to stego-folder
            cover_folders: List of cover folder paths
            stego_key: Dictionary containing credentials, protocol, encryption_key
            max_attempts: Maximum number of extraction attempts
            
        Returns:
            Extracted secret message or None if failed
        """
        
        attempts = 0
        recovered_segments = []
        
        while attempts < max_attempts:
            try:
                self.logger.info(f"Extraction attempt {attempts + 1}/{max_attempts}")
                
                # Precomputation phase (one-time)
                if attempts == 0 or 'hash_maps' not in locals():
                    hash_maps = self.precompute_hash_maps(
                        cover_folders, 
                        stego_key['protocol'], 
                        stego_key['encryption_key']
                    )
                
                # Standard extraction
                encrypted_message = self._standard_extraction(
                    stego_folder, cover_folders, hash_maps, stego_key
                )
                
                # Decrypt message
                secret_message = self.decrypt_message(
                    encrypted_message, stego_key['encryption_key']
                )
                
                self.logger.info("Extraction successful")
                return secret_message
                
            except ExtractionError as e:
                attempts += 1
                self.logger.warning(f"Extraction error: {e}")
                
                # Partial recovery
                partial_result = self._partial_recovery(e)
                if partial_result:
                    recovered_segments.extend(partial_result)
                
                # Check if we have sufficient segments for reconstruction
                if self._sufficient_segments(recovered_segments):
                    reconstructed = self._reconstruct_from_partial(recovered_segments)
                    self.logger.info("Partial recovery successful")
                    return reconstructed
                
                # Exponential backoff
                backoff_time = self.config['backoff_factor'] ** attempts
                self.logger.info(f"Backing off for {backoff_time} seconds")
                time.sleep(backoff_time)
                
            except Exception as e:
                self.logger.error(f"Unexpected error during extraction: {e}")
                attempts += 1
                if attempts >= max_attempts:
                    break
                time.sleep(2 ** attempts)  # Exponential backoff
        
        self.logger.error("Permanent extraction error")
        raise PermanentExtractionError("Failed to extract after maximum attempts")
    
    def _standard_extraction(self, stego_folder: str, cover_folders: List[str],
                           hash_maps: Dict, stego_key: Dict) -> bytes:
        """Standard extraction using precomputed hash maps"""
        encrypted_segments = bytearray()
        
        # Get stego files in sequential order
        stego_files = sorted([
            os.path.join(stego_folder, f) for f in os.listdir(stego_folder)
            if os.path.isfile(os.path.join(stego_folder, f))
        ])
        
        for stego_file in stego_files:
            try:
                with open(stego_file, 'rb') as f:
                    stego_content = f.read()
                
                # Compute HMAC of stego file
                stego_hash = self.compute_hmac(stego_content, stego_key['encryption_key'])
                found = False
                
                # Search in precomputed hash maps
                for folder, folder_data in hash_maps.items():
                    if stego_hash in folder_data['hash_map']:
                        # Found matching file
                        idx = folder_data['hash_map'][stego_hash]
                        
                        # Convert index to binary segment
                        segment_size = (folder_data['file_count'].bit_length() - 1) // 8
                        segment = idx.to_bytes(segment_size, 'big')
                        
                        encrypted_segments.extend(segment)
                        found = True
                        break
                
                if not found:
                    self.logger.warning(f"Stego file {stego_file} not found in any cover folder")
                    
            except Exception as e:
                self.logger.error(f"Error processing stego file {stego_file}: {e}")
                continue
        
        return bytes(encrypted_segments)
    
    def decrypt_message(self, encrypted_data: bytes, key: bytes) -> str:
        """AES-256 decryption"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, AES.block_size)
        
        return decrypted.decode('utf-8')
    
    def _partial_recovery(self, error: Exception) -> List[bytes]:
        """Attempt partial recovery from error"""
        # Implementation depends on error type
        # This is a simplified version
        return []
    
    def _sufficient_segments(self, segments: List[bytes]) -> bool:
        """Check if we have sufficient segments for reconstruction"""
        total_bits = sum(len(s) * 8 for s in segments)
        # Assume we need at least 64 bits for meaningful reconstruction
        return total_bits >= 64
    
    def _reconstruct_from_partial(self, segments: List[bytes]) -> str:
        """Reconstruct message from partial segments"""
        # Simple concatenation - in real implementation would use error correction
        combined = b''.join(segments)
        try:
            # Try to decrypt what we have
            return f"[Partial Recovery] {combined[:50].hex()}..."
        except:
            return "[Partial Data] Could not reconstruct full message"


class ExtractionError(Exception):
    """Custom exception for extraction errors"""
    pass

class PermanentExtractionError(Exception):
    """Exception for permanent extraction failures"""
    pass
