import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import json
from typing import List, Dict, Tuple
import logging

class CCSEmbedder:
    """Implementation of CCS Embedding Algorithm (Algorithm 1)"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def encrypt_message(self, secret_message: str, encryption_key: bytes) -> bytes:
        """AES-256 encryption of secret message"""
        cipher = AES.new(encryption_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(secret_message.encode(), AES.block_size))
        return cipher.iv + ct_bytes
    
    def segment_message(self, encrypted_message: bytes, segment_sizes: List[int]) -> List[bytes]:
        """Segment encrypted message according to folder capacities"""
        segments = []
        idx = 0
        for size in segment_sizes:
            if idx + size <= len(encrypted_message):
                segments.append(encrypted_message[idx:idx+size])
                idx += size
            else:
                # Pad last segment if needed
                segment = encrypted_message[idx:]
                segment += b'\x00' * (size - len(segment))
                segments.append(segment)
                break
        return segments
    
    def apply_protocol(self, files: List[str], protocol: Dict) -> List[str]:
        """Apply contextual protocol to sort files"""
        if protocol['primary_attribute'] == 'content_hash':
            # Sort by SHA-256 hash of file content
            file_hashes = {}
            for file_path in files:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    file_hash = hashlib.sha256(content).hexdigest()
                    file_hashes[file_path] = file_hash
            
            # Secondary sort by file size if specified
            if protocol.get('secondary_attribute') == 'file_size':
                sorted_files = sorted(file_hashes.items(), 
                                     key=lambda x: (x[1], os.path.getsize(x[0])))
            else:
                sorted_files = sorted(file_hashes.items(), key=lambda x: x[1])
            
            if protocol.get('sort_order', 'ascending') == 'descending':
                sorted_files = list(reversed(sorted_files))
                
            return [f[0] for f in sorted_files]
            
        elif protocol['primary_attribute'] == 'file_size':
            # Sort by file size
            sorted_files = sorted(files, key=os.path.getsize)
            if protocol.get('sort_order', 'ascending') == 'descending':
                sorted_files = list(reversed(sorted_files))
            return sorted_files
        
        # Add more protocol implementations as needed
        return sorted(files)
    
    def binary_to_int(self, binary_segment: bytes) -> int:
        """Convert binary segment to integer index"""
        return int.from_bytes(binary_segment, 'big')
    
    def embed(self, secret_message: str, cover_folders: List[str], 
              stego_key: Dict) -> str:
        """
        CCS Embedding Algorithm (Algorithm 1)
        
        Args:
            secret_message: Secret message to hide
            cover_folders: List of cover folder paths
            stego_key: Dictionary containing credentials, protocol, encryption_key
            
        Returns:
            Path to created stego-folder
        """
        
        # Step 1: Connect to cloud (simulated for local testing)
        self.logger.info("Connecting to cloud storage...")
        
        # Step 2: Encrypt secret message
        encryption_key = stego_key['encryption_key']
        encrypted_message = self.encrypt_message(secret_message, encryption_key)
        
        # Step 3: Segment encrypted message
        # Calculate segment sizes based on folder capacities
        segment_sizes = []
        for folder in cover_folders:
            files = [os.path.join(folder, f) for f in os.listdir(folder) 
                    if os.path.isfile(os.path.join(folder, f))]
            capacity = len(files).bit_length() - 1  # floor(log2(M))
            segment_sizes.append(capacity // 8)  # Convert bits to bytes
        
        segments = self.segment_message(encrypted_message, segment_sizes)
        
        # Step 4: Create stego-folder
        stego_folder = os.path.join(os.path.dirname(cover_folders[0]), 
                                   f"stego_folder_{os.urandom(4).hex()}")
        os.makedirs(stego_folder, exist_ok=True)
        
        # Step 5: Process each segment
        for i, segment in enumerate(segments):
            if i >= len(cover_folders):
                break
                
            cover_folder = cover_folders[i]
            files = [os.path.join(cover_folder, f) for f in os.listdir(cover_folder) 
                    if os.path.isfile(os.path.join(cover_folder, f))]
            
            if not files:
                self.logger.warning(f"No files in cover folder {cover_folder}")
                continue
            
            # Apply contextual protocol
            sorted_files = self.apply_protocol(files, stego_key['protocol'])
            
            # Convert segment to index
            idx = self.binary_to_int(segment) % len(sorted_files)
            
            # Select and copy file
            selected_file = sorted_files[idx]
            file_name = os.path.basename(selected_file)
            dest_path = os.path.join(stego_folder, f"{i}_{file_name}")
            
            import shutil
            shutil.copy2(selected_file, dest_path)
            self.logger.info(f"Copied {selected_file} to {dest_path}")
        
        # Step 6: Add decoy files (optional)
        if self.config.get('add_decoy_files', False):
            self._add_decoy_files(stego_folder)
        
        return stego_folder
    
    def _add_decoy_files(self, stego_folder: str, num_decoy: int = 5):
        """Add decoy files for plausible deniability"""
        import random
        import string
        
        for i in range(num_decoy):
            decoy_name = ''.join(random.choices(string.ascii_letters, k=10))
            decoy_path = os.path.join(stego_folder, f"decoy_{decoy_name}.txt")
            with open(decoy_path, 'w') as f:
                f.write(f"Decoy file {i+1} created at {time.time()}\n")
                f.write("".join(random.choices(string.printable, k=1000)))
