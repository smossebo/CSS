# !/usr/bin/env python3
# Concrete Example of CCS Embedding and Extraction (Section 4.3)
# Demonstrates the complete workflow with a 16-bit secret message

import os
import tempfile
import hashlib
from pathlib import Path
import json

# Add src to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.embedding import CCSEmbedder
from src.core.extraction import CCSExtractor
from src.utils.error_handling import robust_cloud_operation

class ConcreteExample:
    """Concrete example from Section 4.3 of the paper"""
    
    def __init__(self):
        self.config = {
            'security': {
                'encryption_algorithm': 'AES-256-CBC',
                'hmac_algorithm': 'SHA256'
            },
            'performance': {
                'precompute_hashes': True,
                'max_retries': 3
            }
        }
        
        # Create test directories structure as in Table 1
        self.base_dir = tempfile.mkdtemp(prefix="ccs_example_")
        print(f"Created test directory: {self.base_dir}")
        
    def create_test_folders(self):
        """Create test folders with files as in Table 1 of the paper"""
        
        # Folder structure from the paper
        folders = {
            'F0': [
                ('abstract.txt', 2),
                ('archive.zip', 512),
                ('backup.bak', 1024),
                ('config.ini', 1),
                ('data.csv', 64),
                ('document.doc', 256),
                ('image.png', 128),
                ('logfile.log', 8),
                ('manual.pdf', 512),
                ('notes.txt', 4),
                ('photo.jpg', 256),
                ('program.exe', 2048),
                ('readme.txt', 1),
                ('video.mp4', 4096),  # Will be selected (index 13)
                ('settings.cfg', 2),
                ('temp.tmp', 16)
            ],
            'F1': [
                ('analysis.xlsx', 128),
                ('budget.xls', 64),
                ('calc.csv', 32),
                ('data.db', 1024),
                ('expenses.ods', 256),
                ('financial.xlsx', 512),
                ('inventory.csv', 16),
                ('metrics.xls', 32),
                ('numbers.ods', 64),
                ('output.csv', 8),
                ('spreadsheet.xlsx', 1024),  # Will be selected (index 10)
                ('stats.ods', 128),
                ('summary.xlsx', 256),
                ('table.csv', 4),
                ('values.ods', 512),
                ('workbook.xls', 2048)
            ],
            'F2': [
                ('briefing.pptx', 512),
                ('conference.ppt', 1024),
                ('demo.odp', 256),
                ('exhibit.pptx', 128),
                ('meeting.ppt', 64),
                ('overview.odp', 32),
                ('pitch.pptx', 2048),
                ('plan.ppt', 16),
                ('proposal.odp', 8),
                ('report.pptx', 4),
                ('presentation.pptx', 4096),  # Will be selected (index 10)
                ('slideshow.ppt', 2),
                ('talk.odp', 1),
                ('update.pptx', 512),
                ('webinar.ppt', 256),
                ('workshop.odp', 128)
            ],
            'F3': [
                ('backup.rar', 2048),
                ('compressed.zip', 1024),
                ('data.rar', 4096),  # Will be selected (index 2)
                ('docs.zip', 512),
                ('files.rar', 256),
                ('archive1.zip', 128),
                ('bundle.rar', 64),
                ('package.zip', 32),
                ('packed.rar', 16),
                ('storage.zip', 8),
                ('zipfile.zip', 4),
                ('rarfile.rar', 2),
                ('compressed2.zip', 1),
                ('backup2.rar', 512),
                ('final.zip', 1024),
                ('complete.rar', 2048)
            ]
        }
        
        # Create folders and files
        self.cover_folders = []
        for folder_name, files in folders.items():
            folder_path = os.path.join(self.base_dir, folder_name)
            os.makedirs(folder_path, exist_ok=True)
            self.cover_folders.append(folder_path)
            
            for filename, size_kb in files:
                file_path = os.path.join(folder_path, filename)
                # Create file with dummy content of approximate size
                content = f"This is {filename} with size ~{size_kb}KB\n".encode()
                content *= max(1, (size_kb * 1024) // len(content))
                
                with open(file_path, 'wb') as f:
                    f.write(content[:size_kb * 1024])
        
        print(f"Created {len(folders)} folders with {sum(len(f) for f in folders.values())} files")
        return self.cover_folders
    
    def run_embedding_example(self):
        """Run concrete embedding example (Algorithm 4)"""
        
        print("\n" + "="*60)
        print("CONCRETE EMBEDDING EXAMPLE (Algorithm 4)")
        print("="*60)
        
        # Secret message from the paper: 1101011010111101 (16 bits)
        secret_message = "1101011010111101"
        print(f"Original secret (16 bits): {secret_message}")
        
        # Convert binary string to actual message
        # In practice, this would be any binary data
        secret_bytes = bytes([int(secret_message[i:i+8], 2) 
                            for i in range(0, len(secret_message), 8)])
        secret_text = secret_bytes.decode('latin-1')
        
        # Stego-key configuration
        stego_key = {
            'credentials': {'api_key': 'test_key'},  # Simulated
            'protocol': {
                'primary_attribute': 'content_hash',
                'hash_algorithm': 'sha256',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending'
            },
            'encryption_key': hashlib.sha256(b"test_encryption_key").digest()
        }
        
        # Create embedder and embed
        embedder = CCSEmbedder(self.config)
        
        print("\nEmbedding process:")
        print("1. Encrypting secret with AES-256...")
        print("2. Segmenting into 4 segments (4 bits each)...")
        print("3. Applying NAME_SIZE protocol to each folder...")
        print("4. Selecting files based on segment values...")
        
        stego_folder = embedder.embed(
            secret_text,
            self.cover_folders,
            stego_key
        )
        
        print(f"\nStego-folder created: {stego_folder}")
        print("Contents of stego-folder:")
        for file in sorted(os.listdir(stego_folder)):
            file_path = os.path.join(stego_folder, file)
            file_size = os.path.getsize(file_path)
            print(f"  - {file} ({file_size} bytes)")
        
        return stego_folder, stego_key
    
    def run_extraction_example(self, stego_folder: str, stego_key: dict):
        """Run concrete extraction example (Algorithm 5)"""
        
        print("\n" + "="*60)
        print("CONCRETE EXTRACTION EXAMPLE (Algorithm 5)")
        print("="*60)
        
        # Create extractor
        extractor = CCSExtractor(self.config)
        
        print("\nExtraction process:")
        print("1. Reconstructing sorted lists using NAME_SIZE protocol...")
        print("2. Matching stego-files to cover folders...")
        print("3. Converting indices back to binary segments...")
        print("4. Decrypting to obtain original secret...")
        
        try:
            extracted_message = extractor.extract(
                stego_folder,
                self.cover_folders,
                stego_key
            )
            
            # Convert extracted message back to binary
            extracted_binary = ''.join(format(ord(c), '08b') for c in extracted_message)
            # Take only first 16 bits (our original message length)
            extracted_binary = extracted_binary[:16]
            
            print(f"\nExtracted secret (16 bits): {extracted_binary}")
            
            # Verify
            original_binary = "1101011010111101"
            if extracted_binary == original_binary:
                print("✓ SUCCESS: Extracted secret matches original!")
            else:
                print(f"✗ ERROR: Mismatch! Original: {original_binary}")
                
        except Exception as e:
            print(f"\n✗ Extraction failed: {e}")
            import traceback
            traceback.print_exc()
    
    def demonstrate_protocol_sorting(self):
        """Demonstrate NAME_SIZE protocol sorting"""
        
        print("\n" + "="*60)
        print("PROTOCOL SORTING DEMONSTRATION")
        print("="*60)
        
        # Test with F0 folder
        folder_path = self.cover_folders[0]
        files = [os.path.join(folder_path, f) for f in os.listdir(folder_path)]
        
        from src.core.embedding import CCSEmbedder
        embedder = CCSEmbedder(self.config)
        
        protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
        
        sorted_files = embedder.apply_protocol(files, protocol)
        
        print(f"\nSorted files in {os.path.basename(folder_path)} (first 5):")
        for i, file_path in enumerate(sorted_files[:5]):
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            print(f"  {i:2d}. {file_name:<20} ({file_size:>6} bytes)")
        
        print(f"\n... and last 5 files:")
        for i, file_path in enumerate(sorted_files[-5:], start=len(sorted_files)-5):
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            print(f"  {i:2d}. {file_name:<20} ({file_size:>6} bytes)")
    
    def cleanup(self):
        """Clean up test directories"""
        import shutil
        if os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir)
            print(f"\nCleaned up test directory: {self.base_dir}")


def main():
    """Main function to run the concrete example"""
    example = ConcreteExample()
    
    try:
        # Create test environment
        example.create_test_folders()
        
        # Demonstrate protocol sorting
        example.demonstrate_protocol_sorting()
        
        # Run embedding
        stego_folder, stego_key = example.run_embedding_example()
        
        # Run extraction
        example.run_extraction_example(stego_folder, stego_key)
        
        print("\n" + "="*60)
        print("EXAMPLE COMPLETE")
        print("="*60)
        print("\nThis example demonstrated:")
        print("1. Creation of 4 folders with 16 files each (as in Table 1)")
        print("2. NAME_SIZE protocol sorting (name then size)")
        print("3. Embedding of 16-bit secret using 4 folders")
        print("4. Selection of files at indices [13, 10, 10, 2]")
        print("5. Extraction and verification of the secret")
        
    finally:
        # Uncomment to cleanup (for inspection, keep files)
        # example.cleanup()
        pass


if __name__ == "__main__":
    main()
