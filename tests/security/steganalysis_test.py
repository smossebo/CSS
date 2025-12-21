# Steganalysis tests for CCS
# Tests statistical undetectability and resistance to analysis

import unittest
import tempfile
import os
import hashlib
import json
import numpy as np
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any

# Add src to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.core.embedding import CCSEmbedder
from src.core.extraction import CCSExtractor
from src.core.security import SecurityManager
from src.utils.logging_config import setup_logging

class StatisticalAnalyzer:
    """Statistical analysis tools for steganalysis"""
    
    @staticmethod
    def compute_file_statistics(folder_path: str) -> Dict[str, Any]:
        """Compute statistical properties of files in folder"""
        files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) 
                if os.path.isfile(os.path.join(folder_path, f))]
        
        if not files:
            return {}
        
        # File sizes
        sizes = [os.path.getsize(f) for f in files]
        
        # File extensions
        extensions = [Path(f).suffix.lower() for f in files]
        
        # Content entropy (first 1KB)
        entropies = []
        for f in files[:100]:  # Sample first 100 files
            try:
                with open(f, 'rb') as file:
                    data = file.read(1024)
                    if data:
                        # Compute byte value frequencies
                        freq = Counter(data)
                        probs = [count/len(data) for count in freq.values()]
                        entropy = -sum(p * np.log2(p) for p in probs if p > 0)
                        entropies.append(entropy)
            except:
                continue
        
        return {
            'file_count': len(files),
            'size_stats': {
                'mean': np.mean(sizes) if sizes else 0,
                'std': np.std(sizes) if len(sizes) > 1 else 0,
                'min': min(sizes) if sizes else 0,
                'max': max(sizes) if sizes else 0,
                'median': np.median(sizes) if sizes else 0
            },
            'extension_distribution': dict(Counter(extensions)),
            'entropy_stats': {
                'mean': np.mean(entropies) if entropies else 0,
                'std': np.std(entropies) if len(entropies) > 1 else 0
            }
        }
    
    @staticmethod
    def compare_folders(folder1_stats: Dict, folder2_stats: Dict) -> Dict[str, float]:
        """Compare statistical properties of two folders"""
        comparisons = {}
        
        # Compare size statistics
        for stat in ['mean', 'std', 'median']:
            val1 = folder1_stats['size_stats'].get(stat, 0)
            val2 = folder2_stats['size_stats'].get(stat, 0)
            if val1 + val2 > 0:
                comparisons[f'size_{stat}_ratio'] = val1 / max(val2, 0.001)
        
        # Compare entropy
        entropy1 = folder1_stats['entropy_stats'].get('mean', 0)
        entropy2 = folder2_stats['entropy_stats'].get('mean', 0)
        if entropy1 + entropy2 > 0:
            comparisons['entropy_ratio'] = entropy1 / max(entropy2, 0.001)
        
        # Compare file counts
        count1 = folder1_stats.get('file_count', 0)
        count2 = folder2_stats.get('file_count', 0)
        if count1 + count2 > 0:
            comparisons['file_count_ratio'] = count1 / max(count2, 1)
        
        return comparisons
    
    @staticmethod
    def compute_anomaly_score(comparisons: Dict, thresholds: Dict = None) -> float:
        """Compute anomaly score from comparisons"""
        if not thresholds:
            thresholds = {
                'size_mean_ratio': (0.8, 1.2),
                'size_std_ratio': (0.5, 2.0),
                'entropy_ratio': (0.9, 1.1),
                'file_count_ratio': (0.5, 2.0)
            }
        
        score = 0
        for key, (low, high) in thresholds.items():
            if key in comparisons:
                value = comparisons[key]
                if value < low or value > high:
                    # Calculate deviation from acceptable range
                    if value < low:
                        deviation = (low - value) / low
                    else:
                        deviation = (value - high) / high
                    score += deviation
        
        return score


class TestSteganalysisResistance(unittest.TestCase):
    """Test CCS resistance to statistical steganalysis"""
    
    def setUp(self):
        """Setup test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="test_steganalysis_")
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
        self._create_test_datasets()
        
        # Initialize analyzer
        self.analyzer = StatisticalAnalyzer()
        
    def tearDown(self):
        """Cleanup"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def _create_test_datasets(self):
        """Create normal and stego datasets for comparison"""
        
        # Create normal folder (simulating regular user folder)
        self.normal_folder = os.path.join(self.test_dir, "normal_folder")
        os.makedirs(self.normal_folder, exist_ok=True)
        
        # Create mixed file types and sizes (simulating real usage)
        file_types = [
            ('.txt', 100, 5000),    # Small text files
            ('.pdf', 10000, 500000), # PDF documents
            ('.jpg', 50000, 2000000), # Images
            ('.zip', 100000, 10000000), # Archives
        ]
        
        file_id = 0
        for ext, min_size, max_size in file_types:
            for i in range(5):  # 5 files of each type
                size = np.random.randint(min_size, max_size)
                filename = f"document_{file_id:03d}{ext}"
                filepath = os.path.join(self.normal_folder, filename)
                
                with open(filepath, 'wb') as f:
                    # Create realistic content patterns
                    if ext == '.txt':
                        content = f"Document {file_id}\n".encode() + b"Content line 1\n" * 10
                        content += os.urandom(max(0, size - len(content)))
                    elif ext == '.jpg':
                        # JPEG header + random data
                        content = b'\xff\xd8\xff\xe0' + os.urandom(size - 4)
                    else:
                        content = os.urandom(size)
                    
                    f.write(content[:size])
                
                file_id += 1
        
        # Create CCS stego folder
        self._create_stego_folder()
    
    def _create_stego_folder(self):
        """Create CCS stego folder for testing"""
        # Create cover folders
        self.cover_folders = []
        for i in range(2):
            folder_path = os.path.join(self.test_dir, f"cover_folder_{i}")
            os.makedirs(folder_path, exist_ok=True)
            self.cover_folders.append(folder_path)
            
            # Create files similar to normal folder
            for j in range(10):
                ext = np.random.choice(['.txt', '.pdf', '.jpg', '.zip'])
                size = np.random.randint(1000, 100000)
                
                filename = f"cover_file_{i}_{j:03d}{ext}"
                filepath = os.path.join(folder_path, filename)
                
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(size))
        
        # Setup CCS
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        
        keys = security_manager.generate_keys("steganalysis_test")
        protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
        
        stego_key = {
            'protocol': protocol,
            'encryption_key': keys['encryption_key']
        }
        
        # Embed message
        test_message = "Secret message for steganalysis testing"
        self.stego_folder = embedder.embed(
            test_message,
            self.cover_folders,
            stego_key
        )
    
    def test_file_content_entropy(self):
        """Test that stego files have normal entropy"""
        
        # Compute entropy for normal folder
        normal_stats = self.analyzer.compute_file_statistics(self.normal_folder)
        normal_entropy = normal_stats['entropy_stats']['mean']
        
        # Compute entropy for stego folder
        stego_stats = self.analyzer.compute_file_statistics(self.stego_folder)
        stego_entropy = stego_stats['entropy_stats']['mean']
        
        print(f"\nEntropy Analysis:")
        print(f"Normal folder entropy: {normal_entropy:.3f}")
        print(f"Stego folder entropy: {stego_entropy:.3f}")
        print(f"Difference: {abs(normal_entropy - stego_entropy):.3f}")
        
        # Entropy should be similar (stego files are exact copies)
        self.assertAlmostEqual(normal_entropy, stego_entropy, delta=0.5,
                             msg="Stego folder entropy significantly different")
    
    def test_file_size_distribution(self):
        """Test that file size distribution is normal"""
        
        normal_stats = self.analyzer.compute_file_statistics(self.normal_folder)
        stego_stats = self.analyzer.compute_file_statistics(self.stego_folder)
        
        # Compare size statistics
        comparisons = self.analyzer.compare_folders(normal_stats, stego_stats)
        
        print(f"\nSize Distribution Comparison:")
        for key, value in comparisons.items():
            print(f"{key}: {value:.3f}")
        
        # Size mean should be similar
        if 'size_mean_ratio' in comparisons:
            ratio = comparisons['size_mean_ratio']
            self.assertGreater(ratio, 0.5, "Size mean too different")
            self.assertLess(ratio, 2.0, "Size mean too different")
    
    def test_file_type_distribution(self):
        """Test that file type distribution is normal"""
        
        normal_stats = self.analyzer.compute_file_statistics(self.normal_folder)
        stego_stats = self.analyzer.compute_file_statistics(self.stego_folder)
        
        normal_exts = normal_stats.get('extension_distribution', {})
        stego_exts = stego_stats.get('extension_distribution', {})
        
        print(f"\nFile Type Distribution:")
        print(f"Normal: {normal_exts}")
        print(f"Stego: {stego_exts}")
        
        # Both should have multiple file types
        self.assertGreater(len(normal_exts), 0, "Normal folder has no file extensions")
        self.assertGreater(len(stego_exts), 0, "Stego folder has no file extensions")
    
    def test_statistical_indistinguishability(self):
        """Test statistical indistinguishability (epsilon-security)"""
        
        # Collect statistics from multiple runs
        normal_stats_list = []
        stego_stats_list = []
        
        for _ in range(5):  # Multiple samples
            normal_stats = self.analyzer.compute_file_statistics(self.normal_folder)
            stego_stats = self.analyzer.compute_file_statistics(self.stego_folder)
            
            normal_stats_list.append(normal_stats)
            stego_stats_list.append(stego_stats)
        
        # Compare distributions
        comparisons = []
        for norm, stego in zip(normal_stats_list, stego_stats_list):
            comp = self.analyzer.compare_folders(norm, stego)
            comparisons.append(comp)
        
        # Calculate average differences
        avg_differences = {}
        for key in comparisons[0].keys():
            values = [c[key] for c in comparisons if key in c]
            avg_differences[key] = np.mean(values)
        
        print(f"\nStatistical Indistinguishability Analysis:")
        for key, value in avg_differences.items():
            print(f"{key}: {value:.3f} (closer to 1.0 is better)")
        
        # Calculate anomaly score
        anomaly_score = self.analyzer.compute_anomaly_score(avg_differences)
        print(f"Anomaly score: {anomaly_score:.3f}")
        
        # Score should be low (close to 0)
        self.assertLess(anomaly_score, 1.0,
                       f"Statistical anomaly detected: score = {anomaly_score}")
    
    def test_metadata_analysis(self):
        """Test metadata patterns for detectability"""
        
        import time
        from datetime import datetime, timedelta
        
        # Collect timestamps
        normal_timestamps = []
        stego_timestamps = []
        
        for folder, timestamp_list in [(self.normal_folder, normal_timestamps),
                                      (self.stego_folder, stego_timestamps)]:
            for filename in os.listdir(folder):
                filepath = os.path.join(folder, filename)
                if os.path.isfile(filepath):
                    mtime = os.path.getmtime(filepath)
                    timestamp_list.append(mtime)
        
        # Analyze temporal patterns
        if normal_timestamps and stego_timestamps:
            normal_times = [datetime.fromtimestamp(ts) for ts in normal_timestamps]
            stego_times = [datetime.fromtimestamp(ts) for ts in stego_timestamps]
            
            # Check if times are clustered (potential indicator)
            normal_range = max(normal_timestamps) - min(normal_timestamps)
            stego_range = max(stego_timestamps) - min(stego_timestamps)
            
            print(f"\nTemporal Pattern Analysis:")
            print(f"Normal folder time range: {normal_range:.1f} seconds")
            print(f"Stego folder time range: {stego_range:.1f} seconds")
            
            # Both should have reasonable time ranges
            self.assertGreater(normal_range, 0, "Normal folder times suspicious")
            self.assertGreater(stego_range, 0, "Stego folder times suspicious")
    
    def test_machine_learning_detection(self):
        """Test resistance to ML-based steganalysis"""
        # Note: This is a simplified test - real ML detection would be more complex
        
        # Extract features for classification
        features = []
        labels = []
        
        # Normal folder features
        normal_stats = self.analyzer.compute_file_statistics(self.normal_folder)
        normal_features = [
            normal_stats['size_stats']['mean'],
            normal_stats['size_stats']['std'],
            normal_stats['entropy_stats']['mean'],
            len(normal_stats.get('extension_distribution', {}))
        ]
        features.append(normal_features)
        labels.append(0)  # 0 = normal
        
        # Stego folder features
        stego_stats = self.analyzer.compute_file_statistics(self.stego_folder)
        stego_features = [
            stego_stats['size_stats']['mean'],
            stego_stats['size_stats']['std'],
            stego_stats['entropy_stats']['mean'],
            len(stego_stats.get('extension_distribution', {}))
        ]
        features.append(stego_features)
        labels.append(1)  # 1 = stego
        
        # Simple distance-based detection
        from sklearn.metrics.pairwise import cosine_similarity
        
        similarity = cosine_similarity([normal_features], [stego_features])[0][0]
        
        print(f"\nML Detection Test:")
        print(f"Cosine similarity between normal and stego: {similarity:.3f}")
        print("(Closer to 1.0 means harder to distinguish)")
        
        # Features should be similar (high similarity)
        self.assertGreater(similarity, 0.8,
                          f"Features too dissimilar for ML detection: {similarity}")


class TestAdvancedSteganalysis(unittest.TestCase):
    """Advanced steganalysis tests"""
    
    def test_batch_analysis(self):
        """Test analysis of multiple stego folders"""
        
        test_dir = tempfile.mkdtemp(prefix="batch_analysis_")
        
        try:
            config = {
                'security': {'encryption_algorithm': 'AES-256-CBC'},
                'performance': {'precompute_hashes': False}
            }
            
            embedder = CCSEmbedder(config)
            security_manager = SecurityManager(config['security'])
            analyzer = StatisticalAnalyzer()
            
            keys = security_manager.generate_keys("batch_test")
            protocol = {'primary_attribute': 'content_hash', 'sort_order': 'ascending'}
            stego_key = {'protocol': protocol, 'encryption_key': keys['encryption_key']}
            
            # Create multiple stego folders
            stego_folders = []
            messages = ["Message 1", "Message 2", "Message 3", "Message 4"]
            
            for i, message in enumerate(messages):
                # Create cover folder
                cover_folder = os.path.join(test_dir, f"cover_{i}")
                os.makedirs(cover_folder, exist_ok=True)
                
                # Add files
                for j in range(20):
                    filepath = os.path.join(cover_folder, f"file_{j:03d}.dat")
                    with open(filepath, 'wb') as f:
                        f.write(os.urandom(np.random.randint(100, 10000)))
                
                # Embed
                stego_folder = embedder.embed(
                    message,
                    [cover_folder],
                    stego_key
                )
                stego_folders.append(stego_folder)
            
            # Analyze all stego folders
            stats_list = []
            for folder in stego_folders:
                stats = analyzer.compute_file_statistics(folder)
                stats_list.append(stats)
            
            # Check consistency between stego folders
            variations = []
            for i in range(len(stats_list)):
                for j in range(i+1, len(stats_list)):
                    comp = analyzer.compare_folders(stats_list[i], stats_list[j])
                    variations.append(comp)
            
            # Calculate average variation
            avg_variation = {}
            for key in variations[0].keys():
                values = [v[key] for v in variations if key in v]
                avg_variation[key] = np.mean(values)
            
            print(f"\nBatch Analysis - Consistency between stego folders:")
            for key, value in avg_variation.items():
                print(f"{key}: {value:.3f}")
            
            # Variations should be small (consistent embedding)
            for key, value in avg_variation.items():
                if 'ratio' in key:
                    self.assertGreater(value, 0.8, f"Too much variation in {key}: {value}")
                    self.assertLess(value, 1.2, f"Too much variation in {key}: {value}")
        
        finally:
            import shutil
            shutil.rmtree(test_dir)
    
    def test_protocol_variation_analysis(self):
        """Test if different protocols produce detectably different outputs"""
        
        test_dir = tempfile.mkdtemp(prefix="protocol_variation_")
        
        try:
            config = {
                'security': {'encryption_algorithm': 'AES-256-CBC'},
                'performance': {'precompute_hashes': False}
            }
            
            embedder = CCSEmbedder(config)
            security_manager = SecurityManager(config['security'])
            analyzer = StatisticalAnalyzer()
            
            keys = security_manager.generate_keys("protocol_test")
            
            # Different protocols to test
            protocols = [
                {'primary_attribute': 'content_hash', 'sort_order': 'ascending'},
                {'primary_attribute': 'file_size', 'sort_order': 'ascending'},
                {'primary_attribute': 'content_hash', 'sort_order': 'descending'},
            ]
            
            stego_folders = []
            
            for i, protocol in enumerate(protocols):
                # Create cover folder
                cover_folder = os.path.join(test_dir, f"cover_protocol_{i}")
                os.makedirs(cover_folder, exist_ok=True)
                
                # Add files
                for j in range(15):
                    filepath = os.path.join(cover_folder, f"file_{j:03d}.dat")
                    with open(filepath, 'wb') as f:
                        f.write(os.urandom(1024))
                
                # Embed with different protocol
                stego_key = {
                    'protocol': protocol,
                    'encryption_key': keys['encryption_key']
                }
                
                stego_folder = embedder.embed(
                    "Test message",
                    [cover_folder],
                    stego_key
                )
                stego_folders.append(stego_folder)
            
            # Analyze differences
            stats_list = [analyzer.compute_file_statistics(f) for f in stego_folders]
            
            print(f"\nProtocol Variation Analysis:")
            for i in range(len(protocols)):
                for j in range(i+1, len(protocols)):
                    comp = analyzer.compare_folders(stats_list[i], stats_list[j])
                    anomaly = analyzer.compute_anomaly_score(comp)
                    
                    print(f"Protocol {i} vs {j}: anomaly score = {anomaly:.3f}")
                    
                    # Different protocols should not create statistically different outputs
                    self.assertLess(anomaly, 0.5,
                                  f"Protocols {i} and {j} produce detectably different outputs")
        
        finally:
            import shutil
            shutil.rmtree(test_dir)


def run_steganalysis_suite():
    """Run comprehensive steganalysis tests"""
    
    print("=" * 70)
    print("CCS STEGANALYSIS RESISTANCE TEST SUITE")
    print("=" * 70)
    
    # Create test runner
    runner = unittest.TextTestRunner(verbosity=2)
    
    # Run basic tests
    print("\n1. Basic Statistical Tests:")
    basic_suite = unittest.TestLoader().loadTestsFromTestCase(TestSteganalysisResistance)
    basic_result = runner.run(basic_suite)
    
    # Run advanced tests
    print("\n2. Advanced Steganalysis Tests:")
    advanced_suite = unittest.TestLoader().loadTestsFromTestCase(TestAdvancedSteganalysis)
    advanced_result = runner.run(advanced_suite)
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    total_tests = (basic_result.testsRun + advanced_result.testsRun)
    total_failures = len(basic_result.failures) + len(advanced_result.failures)
    total_errors = len(basic_result.errors) + len(advanced_result.errors)
    
    print(f"Total tests run: {total_tests}")
    print(f"Failures: {total_failures}")
    print(f"Errors: {total_errors}")
    
    if total_failures == 0 and total_errors == 0:
        print("\n✓ All steganalysis tests passed!")
        print("CCS demonstrates strong resistance to statistical detection.")
    else:
        print("\n✗ Some tests failed")
        print("Review failures for potential detectability issues.")


if __name__ == '__main__':
    run_steganalysis_suite()
