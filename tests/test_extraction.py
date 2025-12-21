# Unit tests for CCS extraction functionality
# Tests Algorithms 2, 3, 5, and 8

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
from src.core.extraction import CCSExtractor, ExtractionError
from src.core.security import SecurityManager
from src.utils.logging_config import setup_logging

class TestExtraction(unittest.TestCase):
    """Test cases for CCS extraction"""
    
    def setUp(self):
        """Setup test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="test_extraction_")
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
        self._create_test_environment()
        
    def tearDown(self):
        """Cleanup test environment"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def _create_test_environment(self):
        """Create test folders and embed a message"""
        # Create cover folders
        self.cover_folders = []
        for i in range(3):
            folder_path = os.path.join(self.test_dir, f"cover_folder_{i}")
            os.makedirs(folder_path, exist_ok=True)
            self.cover_folders.append(folder_path)
            
            # Create files with unique content
            num_files = [8, 12, 16][i]
            for j in range(num_files):
                file_path = os.path.join(folder_path, f"file_{j:03d}.dat")
                with open(file_path, 'wb') as f:
                    # Use unique content for each file
                    content = f"Unique content for folder {i}, file {j}".encode()
                    content += os.urandom(100)  # Add randomness
                    f.write(content)
        
        # Setup embedding
        self.embedder = CCSEmbedder(self.config)
        self.extractor = CCSExtractor(self.config)
        self.security_manager = SecurityManager(self.config['security'])
        
        # Generate keys
        self.keys = self.security_manager.generate_keys("test_password")
        
        # Define protocol
        self.protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
        
        self.stego_key = {
            'credentials': {},
            'protocol': self.protocol,
            'encryption_key': self.keys['encryption_key']
        }
        
        # Embed test message
        self.test_message = "Test secret message for extraction testing"
        self.stego_folder = self.embedder.embed(
            self.test_message,
            self.cover_folders,
            self.stego_key
        )
    
    def test_extractor_initialization(self):
        """Test CCSExtractor initialization"""
        extractor = CCSExtractor(self.config)
        self.assertIsInstance(extractor, CCSExtractor)
        self.assertIn('security', extractor.config)
    
    def test_hmac_computation(self):
        """Test HMAC computation (Algorithm 3)"""
        extractor = CCSExtractor(self.config)
        
        # Test data
        test_data = b"Test data for HMAC computation"
        test_key = b"test_key_32_bytes_123456789012"
        
        # Compute HMAC
        hmac_value = extractor.compute_hmac(test_data, test_key)
        
        # Verify HMAC properties
        self.assertIsInstance(hmac_value, str)
        self.assertEqual(len(hmac_value), 64)  # SHA256 hex digest length
        
        # Should be deterministic
        hmac_value2 = extractor.compute_hmac(test_data, test_key)
        self.assertEqual(hmac_value, hmac_value2)
        
        # Different data should produce different HMAC
        hmac_diff = extractor.compute_hmac(b"Different data", test_key)
        self.assertNotEqual(hmac_value, hmac_diff)
    
    def test_precomputation(self):
        """Test hash map precomputation"""
        extractor = CCSExtractor(self.config)
        
        # Precompute hash maps for one folder
        hash_maps = extractor.precompute_hash_maps(
            [self.cover_folders[0]],
            self.protocol,
            self.keys['encryption_key']
        )
        
        # Verify results
        self.assertIsInstance(hash_maps, dict)
        self.assertIn(self.cover_folders[0], hash_maps)
        
        folder_data = hash_maps[self.cover_folders[0]]
        self.assertIn('sorted_files', folder_data)
        self.assertIn('hash_map', folder_data)
        self.assertIn('file_count', folder_data)
        
        # Verify hash map contains entries
        self.assertGreater(len(folder_data['hash_map']), 0)
        
        # Verify indices are within range
        for idx in folder_data['hash_map'].values():
            self.assertGreaterEqual(idx, 0)
            self.assertLess(idx, folder_data['file_count'])
    
    def test_basic_extraction(self):
        """Test basic extraction functionality"""
        extractor = CCSExtractor(self.config)
        
        # Extract message
        extracted_message = extractor.extract(
            self.stego_folder,
            self.cover_folders,
            self.stego_key,
            max_attempts=1
        )
        
        # Verify extraction
        self.assertEqual(extracted_message, self.test_message)
    
    def test_extraction_with_precomputation(self):
        """Test extraction using precomputed hash maps"""
        extractor = CCSExtractor(self.config)
        
        # Precompute hash maps
        hash_maps = extractor.precompute_hash_maps(
            self.cover_folders,
            self.protocol,
            self.keys['encryption_key']
        )
        
        # Extract using standard method (should use precomputation internally)
        extracted_message = extractor.extract(
            self.stego_folder,
            self.cover_folders,
            self.stego_key
        )
        
        self.assertEqual(extracted_message, self.test_message)
    
    def test_file_matching(self):
        """Test secure file matching"""
        extractor = CCSExtractor(self.config)
        
        # Get a file from cover folder
        test_file = os.path.join(self.cover_folders[0], os.listdir(self.cover_folders[0])[0])
        
        # Compute HMAC
        with open(test_file, 'rb') as f:
            content = f.read()
        
        hmac1 = extractor.compute_hmac(content, self.keys['encryption_key'])
        
        # Create a copy (should match)
        temp_file = os.path.join(self.test_dir, "temp_copy.dat")
        with open(temp_file, 'wb') as f:
            f.write(content)
        
        with open(temp_file, 'rb') as f:
            content2 = f.read()
        
        hmac2 = extractor.compute_hmac(content2, self.keys['encryption_key'])
        
        # Should match
        self.assertEqual(hmac1, hmac2)
        
        # Modified content should not match
        modified_content = content + b"modified"
        hmac3 = extractor.compute_hmac(modified_content, self.keys['encryption_key'])
        self.assertNotEqual(hmac1, hmac3)
    
    def test_decryption(self):
        """Test message decryption"""
        extractor = CCSExtractor(self.config)
        
        # Encrypt a test message
        test_message = "Test decryption message"
        iv, ciphertext = self.embedder.encrypt_message(
            test_message,
            self.keys['encryption_key']
        )
        
        # Decrypt
        decrypted = extractor.decrypt_message(
            iv, ciphertext, self.keys['encryption_key']
        )
        
        self.assertEqual(decrypted, test_message)
    
    def test_partial_recovery(self):
        """Test partial recovery functionality"""
        extractor = CCSExtractor(self.config)
        
        # Simulate partial data
        segments = [
            b"partial_segment_1",
            b"partial_segment_2",
            b"partial_segment_3"
        ]
        
        # Test sufficient segments check
        self.assertTrue(extractor._sufficient_segments(segments))
        
        # Test with insufficient data
        insufficient = [b"short"]
        self.assertFalse(extractor._sufficient_segments(insufficient))
    
    def test_error_handling(self):
        """Test extraction error handling"""
        extractor = CCSExtractor(self.config)
        
        # Test with non-existent stego folder
        with self.assertRaises(Exception):
            extractor.extract(
                "/non/existent/folder",
                self.cover_folders,
                self.stego_key
            )
        
        # Test with empty stego folder
        empty_folder = tempfile.mkdtemp()
        try:
            with self.assertRaises(Exception):
                extractor.extract(
                    empty_folder,
                    self.cover_folders,
                    self.stego_key,
                    max_attempts=1
                )
        finally:
            import shutil
            shutil.rmtree(empty_folder)
    
    def test_corrupted_stego_folder(self):
        """Test extraction from corrupted stego folder"""
        extractor = CCSExtractor(self.config)
        
        # Create corrupted stego folder (files not from cover folders)
        corrupted_folder = os.path.join(self.test_dir, "corrupted_stego")
        os.makedirs(corrupted_folder, exist_ok=True)
        
        # Add random files
        for i in range(3):
            file_path = os.path.join(corrupted_folder, f"corrupt_{i}.dat")
            with open(file_path, 'wb') as f:
                f.write(os.urandom(100))
        
        # Should fail to extract
        with self.assertRaises(Exception):
            extractor.extract(
                corrupted_folder,
                self.cover_folders,
                self.stego_key,
                max_attempts=1
            )
    
    def test_missing_cover_folder(self):
        """Test extraction with missing cover folder"""
        extractor = CCSExtractor(self.config)
        
        # Remove one cover folder
        missing_folders = self.cover_folders[:2]  # Only first two folders
        
        # Should fail or recover partially
        with self.assertRaises(Exception):
            extractor.extract(
                self.stego_folder,
                missing_folders,
                self.stego_key,
                max_attempts=1
            )
    
    def test_modified_stego_files(self):
        """Test extraction with modified stego files"""
        extractor = CCSExtractor(self.config)
        
        # Modify a stego file
        stego_files = os.listdir(self.stego_folder)
        if stego_files:
            file_to_modify = os.path.join(self.stego_folder, stego_files[0])
            
            # Backup original content
            with open(file_to_modify, 'rb') as f:
                original_content = f.read()
            
            # Modify file
            with open(file_to_modify, 'wb') as f:
                f.write(original_content + b"MODIFICATION")
            
            try:
                # Extraction should fail due to HMAC mismatch
                with self.assertRaises(Exception):
                    extractor.extract(
                        self.stego_folder,
                        self.cover_folders,
                        self.stego_key,
                        max_attempts=1
                    )
            finally:
                # Restore original file
                with open(file_to_modify, 'wb') as f:
                    f.write(original_content)
    
    def test_large_message_extraction(self):
        """Test extraction of large messages"""
        extractor = CCSExtractor(self.config)
        
        # Create large test message
        large_message = "Large message " * 1000
        
        # Embed large message
        large_stego_folder = self.embedder.embed(
            large_message,
            self.cover_folders,
            self.stego_key
        )
        
        # Extract
        extracted = extractor.extract(
            large_stego_folder,
            self.cover_folders,
            self.stego_key
        )
        
        self.assertEqual(extracted, large_message)
        
        # Cleanup
        import shutil
        shutil.rmtree(large_stego_folder)


class TestFaultTolerantExtraction(unittest.TestCase):
    """Tests for fault-tolerant extraction (Algorithm 8)"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_fault_tolerant_")
        self.config = {
            'security': {'encryption_algorithm': 'AES-256-CBC'},
            'performance': {'precompute_hashes': False},
            'backoff_factor': 2
        }
        
    def tearDown(self):
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_retry_mechanism(self):
        """Test retry mechanism with simulated failures"""
        from unittest.mock import Mock, patch
        
        extractor = CCSExtractor(self.config)
        
        # Mock extractor to fail twice then succeed
        mock_extract = Mock()
        mock_extract.side_effect = [
            ExtractionError("First failure"),
            ExtractionError("Second failure"),
            "Success message"
        ]
        
        with patch.object(extractor, '_standard_extraction', mock_extract):
            # Should succeed after retries
            result = extractor.extract(
                "dummy_folder",
                ["dummy_cover"],
                {"protocol": {}, "encryption_key": b'0'*32},
                max_attempts=3
            )
            
            self.assertEqual(result, "Success message")
            self.assertEqual(mock_extract.call_count, 3)
    
    def test_max_attempts_exceeded(self):
        """Test behavior when max attempts exceeded"""
        extractor = CCSExtractor(self.config)
        
        # Create a scenario that will always fail
        with self.assertRaises(Exception) as context:
            extractor.extract(
                "/non/existent",
                ["/also/non/existent"],
                {"protocol": {}, "encryption_key": b'0'*32},
                max_attempts=2
            )
        
        self.assertIn("Permanent extraction error", str(context.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
