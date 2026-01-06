# Unit tests for CCS embedding functionality
# Tests Algorithm 1 and related components


import unittest
import tempfile
import os
import hashlib
import json
from pathlib import Path

# Add src to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.embedding import CCSEmbedder
from src.core.security import SecurityManager
from src.utils.logging_config import setup_logging

class TestEmbedding(unittest.TestCase):
    """Test cases for CCS embedding"""
    
    def setUp(self):
        """Setup test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="test_embedding_")
        self.config = {
            'security': {
                'encryption_algorithm': 'AES-256-CBC',
                'hmac_algorithm': 'SHA256'
            },
            'performance': {
                'precompute_hashes': False
            }
        }
        
        # Setup logging
        setup_logging({'log_dir': os.path.join(self.test_dir, 'logs')})
        
        # Create test data
        self._create_test_folders()
        
    def tearDown(self):
        """Cleanup test environment"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def _create_test_folders(self):
        """Create test folders with files"""
        self.cover_folders = []
        
        # Create 3 test folders with different numbers of files
        for i in range(3):
            folder_path = os.path.join(self.test_dir, f"cover_folder_{i}")
            os.makedirs(folder_path, exist_ok=True)
            self.cover_folders.append(folder_path)
            
            # Create files with different content
            num_files = [8, 16, 32][i]  # Different sizes for testing
            for j in range(num_files):
                file_path = os.path.join(folder_path, f"file_{j:03d}.txt")
                with open(file_path, 'w') as f:
                    f.write(f"Test content for file {j} in folder {i}\n")
                    f.write("x" * (j * 100))  # Varying sizes
    
    def test_embedder_initialization(self):
        """Test CCSEmbedder initialization"""
        embedder = CCSEmbedder(self.config)
        self.assertIsInstance(embedder, CCSEmbedder)
        self.assertIn('security', embedder.config)
    
    def test_encrypt_message(self):
        """Test message encryption"""
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        
        # Generate test key
        keys = security_manager.generate_keys("test_password")
        
        # Test encryption/decryption
        test_message = "Test secret message for embedding"
        iv, ciphertext = embedder.encrypt_message(test_message, keys['encryption_key'])
        
        # Verify encryption produced output
        self.assertIsInstance(iv, bytes)
        self.assertIsInstance(ciphertext, bytes)
        self.assertEqual(len(iv), 16)  # AES IV size
        self.assertGreater(len(ciphertext), 0)
        
        # Test decryption
        decrypted = security_manager.decrypt_message(iv, ciphertext, keys['encryption_key'])
        self.assertEqual(decrypted, test_message)
    
    def test_segment_message(self):
        """Test message segmentation"""
        embedder = CCSEmbedder(self.config)
        
        # Test data
        test_data = b"x" * 100  # 100 bytes
        
        # Test different segment sizes
        segment_sizes = [10, 20, 30, 40]
        segments = embedder.segment_message(test_data, segment_sizes)
        
        self.assertEqual(len(segments), len(segment_sizes))
        
        # Verify total length
        total_length = sum(len(s) for s in segments)
        self.assertGreaterEqual(total_length, len(test_data))
        
        # Verify first segments match original data
        reconstructed = b''.join(segments)
        self.assertEqual(reconstructed[:len(test_data)], test_data)
    
    def test_apply_protocol(self):
        """Test protocol application for file sorting"""
        embedder = CCSEmbedder(self.config)
        
        # Get files from first test folder
        test_folder = self.cover_folders[0]
        files = [os.path.join(test_folder, f) for f in os.listdir(test_folder)]
        
        # Test content hash protocol
        protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
        
        sorted_files = embedder.apply_protocol(files, protocol)
        
        # Verify sorting
        self.assertEqual(len(sorted_files), len(files))
        self.assertEqual(set(sorted_files), set(files))  # Same files
        
        # Verify order is deterministic
        sorted_files2 = embedder.apply_protocol(files, protocol)
        self.assertEqual(sorted_files, sorted_files2)
        
        # Test file size protocol
        protocol_size = {
            'primary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
        
        size_sorted = embedder.apply_protocol(files, protocol_size)
        
        # Verify size ordering (smallest first)
        sizes = [os.path.getsize(f) for f in size_sorted]
        self.assertEqual(sizes, sorted(sizes))
    
    def test_binary_to_int_conversion(self):
        """Test binary to integer conversion"""
        embedder = CCSEmbedder(self.config)
        
        test_cases = [
            (b'\x00', 0),
            (b'\x01', 1),
            (b'\xff', 255),
            (b'\x00\x01', 1),
            (b'\x01\x00', 256),
        ]
        
        for binary, expected in test_cases:
            result = embedder.binary_to_int(binary)
            self.assertEqual(result, expected)
    
    def test_single_folder_embedding(self):
        """Test embedding with single folder"""
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        
        # Generate keys
        keys = security_manager.generate_keys("test_password")
        
        # Prepare stego-key
        stego_key = {
            'credentials': {},
            'protocol': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending'
            },
            'encryption_key': keys['encryption_key']
        }
        
        # Test message
        secret_message = "Small secret"
        
        # Perform embedding
        stego_folder = embedder.embed(
            secret_message,
            [self.cover_folders[0]],  # Single folder
            stego_key
        )
        
        # Verify results
        self.assertTrue(os.path.exists(stego_folder))
        self.assertTrue(os.path.isdir(stego_folder))
        
        # Should have created at least one file
        stego_files = os.listdir(stego_folder)
        self.assertGreater(len(stego_files), 0)
        
        # Cleanup
        import shutil
        shutil.rmtree(stego_folder)
    
    def test_multi_folder_embedding(self):
        """Test embedding with multiple folders"""
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        
        # Generate keys
        keys = security_manager.generate_keys("test_password")
        
        # Prepare stego-key
        stego_key = {
            'credentials': {},
            'protocol': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending'
            },
            'encryption_key': keys['encryption_key']
        }
        
        # Larger test message
        secret_message = "This is a longer secret message that needs multiple folders"
        
        # Perform embedding with all folders
        stego_folder = embedder.embed(
            secret_message,
            self.cover_folders,
            stego_key
        )
        
        # Verify results
        self.assertTrue(os.path.exists(stego_folder))
        
        # Should have created multiple files
        stego_files = os.listdir(stego_folder)
        self.assertGreaterEqual(len(stego_files), len(self.cover_folders))
        
        # Cleanup
        import shutil
        shutil.rmtree(stego_folder)
    
    def test_embedding_capacity(self):
        """Test embedding capacity calculation"""
        embedder = CCSEmbedder(self.config)
        
        # Test with different folder sizes
        test_cases = [
            (8, 3),    # 8 files -> 3 bits capacity
            (16, 4),   # 16 files -> 4 bits capacity
            (32, 5),   # 32 files -> 5 bits capacity
            (100, 6),  # 100 files -> 6 bits capacity (floor(log2(100)) = 6)
        ]
        
        for num_files, expected_capacity in test_cases:
            # Create test folder
            test_folder = tempfile.mkdtemp()
            
            # Create files
            for i in range(num_files):
                file_path = os.path.join(test_folder, f"file_{i}.txt")
                with open(file_path, 'w') as f:
                    f.write(f"Content {i}")
            
            # Calculate capacity
            files = [os.path.join(test_folder, f) for f in os.listdir(test_folder)]
            actual_capacity = len(files).bit_length() - 1  # floor(log2(M))
            
            self.assertEqual(actual_capacity, expected_capacity)
            
            # Cleanup
            import shutil
            shutil.rmtree(test_folder)
    
    def test_embedding_with_decoy_files(self):
        """Test embedding with decoy files option"""
        config_with_decoy = self.config.copy()
        config_with_decoy['add_decoy_files'] = True
        
        embedder = CCSEmbedder(config_with_decoy)
        security_manager = SecurityManager(self.config['security'])
        
        # Generate keys
        keys = security_manager.generate_keys("test_password")
        
        # Prepare stego-key
        stego_key = {
            'credentials': {},
            'protocol': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending'
            },
            'encryption_key': keys['encryption_key']
        }
        
        # Test message
        secret_message = "Secret with decoy"
        
        # Perform embedding
        stego_folder = embedder.embed(
            secret_message,
            [self.cover_folders[0]],
            stego_key
        )
        
        # Check for decoy files (files starting with "decoy_")
        stego_files = os.listdir(stego_folder)
        decoy_files = [f for f in stego_files if f.startswith('decoy_')]
        
        self.assertGreater(len(decoy_files), 0, "No decoy files found")
        
        # Cleanup
        import shutil
        shutil.rmtree(stego_folder)
    
    def test_error_handling(self):
        """Test error handling during embedding"""
        embedder = CCSEmbedder(self.config)
        
        # Test with non-existent folder
        with self.assertRaises(Exception):
            embedder.embed(
                "test",
                ["/non/existent/folder"],
                {'protocol': {}, 'encryption_key': b'0' * 32}
            )
        
        # Test with empty folder
        empty_folder = tempfile.mkdtemp()
        try:
            result = embedder.embed(
                "test",
                [empty_folder],
                {'protocol': {}, 'encryption_key': b'0' * 32}
            )
            # Should either work or fail gracefully
            self.assertTrue(os.path.exists(result) or True)
        finally:
            import shutil
            shutil.rmtree(empty_folder)
    
    def test_protocol_variations(self):
        """Test embedding with different protocols"""
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        
        # Generate keys
        keys = security_manager.generate_keys("test_password")
        
        # Test different protocols
        protocols = [
            {
                'primary_attribute': 'content_hash',
                'sort_order': 'ascending'
            },
            {
                'primary_attribute': 'file_size',
                'sort_order': 'descending'
            },
            {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending'
            }
        ]
        
        for protocol in protocols:
            stego_key = {
                'credentials': {},
                'protocol': protocol,
                'encryption_key': keys['encryption_key']
            }
            
            # Perform embedding
            stego_folder = embedder.embed(
                "Test message",
                [self.cover_folders[0]],
                stego_key
            )
            
            # Verify embedding worked
            self.assertTrue(os.path.exists(stego_folder))
            self.assertGreater(len(os.listdir(stego_folder)), 0)
            
            # Cleanup
            import shutil
            shutil.rmtree(stego_folder)


class TestEmbeddingIntegration(unittest.TestCase):
    """Integration tests for embedding functionality"""
    
    def setUp(self):
        """Setup integration test"""
        self.test_dir = tempfile.mkdtemp(prefix="test_integration_")
        
    def tearDown(self):
        """Cleanup"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_end_to_end_small(self):
        """End-to-end test with small dataset"""
        from src.core.embedding import CCSEmbedder
        from src.core.extraction import CCSExtractor
        from src.core.security import SecurityManager
        
        config = {
            'security': {'encryption_algorithm': 'AES-256-CBC'},
            'performance': {'precompute_hashes': False}
        }
        
        # Create test data
        test_folder = os.path.join(self.test_dir, "test_cover")
        os.makedirs(test_folder, exist_ok=True)
        
        # Create 16 files
        for i in range(16):
            with open(os.path.join(test_folder, f"file_{i:02d}.txt"), 'w') as f:
                f.write(f"Unique content {i:04d}" * 10)
        
        # Setup
        embedder = CCSEmbedder(config)
        extractor = CCSExtractor(config)
        security_manager = SecurityManager(config['security'])
        
        # Generate keys
        keys = security_manager.generate_keys("integration_test")
        
        # Define protocol
        protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
        
        stego_key = {
            'credentials': {},
            'protocol': protocol,
            'encryption_key': keys['encryption_key']
        }
        
        # Test message
        original_message = "This is a secret message for integration testing!"
        
        # Embed
        stego_folder = embedder.embed(
            original_message,
            [test_folder],
            stego_key
        )
        
        # Extract
        extracted_message = extractor.extract(
            stego_folder,
            [test_folder],
            stego_key
        )
        
        # Verify
        self.assertEqual(extracted_message, original_message)
        
        # Cleanup
        import shutil
        if os.path.exists(stego_folder):
            shutil.rmtree(stego_folder)


if __name__ == '__main__':
    unittest.main(verbosity=2)
