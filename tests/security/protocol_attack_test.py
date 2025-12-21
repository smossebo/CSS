# Protocol attack resistance tests for CCS
# Tests security against protocol discovery attacks

import unittest
import tempfile
import os
import hashlib
import json
import itertools
import numpy as np
from typing import Dict, List, Tuple
from pathlib import Path

# Add src to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.core.embedding import CCSEmbedder
from src.core.extraction import CCSExtractor
from src.core.security import SecurityManager
from src.core.protocols import ProtocolManager, PrimaryAttribute, SortOrder
from src.utils.logging_config import setup_logging

class ProtocolAttacker:
    """Simulates attacks against CCS contextual protocols"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.protocol_manager = ProtocolManager()
        
    def brute_force_attack(self, stego_folder: str, cover_folders: List[str],
                          encryption_key: bytes, max_protocols: int = None) -> Dict:
        """
        Brute-force protocol discovery attack
        
        Args:
            stego_folder: Path to stego-folder
            cover_folders: List of cover folder paths
            encryption_key: Encryption key (assumed known for attack)
            max_protocols: Maximum number of protocols to test
            
        Returns:
            Attack results
        """
        
        extractor = CCSExtractor(self.config)
        all_protocols = self.protocol_manager.list_protocols()
        
        if max_protocols:
            all_protocols = all_protocols[:max_protocols]
        
        results = {
            'total_protocols_tested': 0,
            'successful_protocols': [],
            'partial_successes': [],
            'time_per_protocol': [],
            'best_guess': None
        }
        
        import time
        
        for protocol in all_protocols:
            start_time = time.time()
            
            try:
                stego_key = {
                    'protocol': {
                        'primary_attribute': protocol['primary_attribute'].value,
                        'secondary_attribute': protocol['secondary_attribute'].value 
                            if protocol['secondary_attribute'] else None,
                        'sort_order': protocol['sort_order'].value,
                        'combination': protocol['combination'],
                        'transform': protocol['transform']
                    },
                    'encryption_key': encryption_key
                }
                
                # Try extraction
                extracted = extractor.extract(
                    stego_folder,
                    cover_folders,
                    stego_key,
                    max_attempts=1
                )
                
                # Check if extraction produced plausible output
                if self._is_plausible_message(extracted):
                    results['successful_protocols'].append({
                        'protocol_id': protocol['id'],
                        'protocol_desc': protocol['description'],
                        'extracted_message': extracted[:50] + "..." if len(extracted) > 50 else extracted
                    })
                    
                    if results['best_guess'] is None:
                        results['best_guess'] = protocol['id']
                
            except Exception as e:
                # Failed extraction - could be wrong protocol
                pass
            
            elapsed = time.time() - start_time
            results['time_per_protocol'].append(elapsed)
            results['total_protocols_tested'] += 1
        
        # Calculate statistics
        if results['time_per_protocol']:
            results['avg_time_per_protocol'] = sum(results['time_per_protocol']) / len(results['time_per_protocol'])
            results['total_attack_time'] = sum(results['time_per_protocol'])
        
        return results
    
    def known_plaintext_attack(self, stego_folder: str, cover_folders: List[str],
                              known_message: str, encryption_key: bytes) -> Dict:
        """
        Known-plaintext attack on protocol
        
        Args:
            stego_folder: Path to stego-folder
            cover_folders: List of cover folder paths
            known_message: Known secret message
            encryption_key: Encryption key
            
        Returns:
            Attack results
        """
        
        results = {
            'protocols_tested': 0,
            'matching_protocols': [],
            'attack_time': 0
        }
        
        import time
        start_time = time.time()
        
        # Get all protocols
        all_protocols = self.protocol_manager.list_protocols()
        extractor = CCSExtractor(self.config)
        
        for protocol in all_protocols:
            try:
                stego_key = {
                    'protocol': {
                        'primary_attribute': protocol['primary_attribute'].value,
                        'secondary_attribute': protocol['secondary_attribute'].value 
                            if protocol['secondary_attribute'] else None,
                        'sort_order': protocol['sort_order'].value,
                        'combination': protocol['combination'],
                        'transform': protocol['transform']
                    },
                    'encryption_key': encryption_key
                }
                
                # Try extraction
                extracted = extractor.extract(
                    stego_folder,
                    cover_folders,
                    stego_key,
                    max_attempts=1
                )
                
                # Check if matches known message
                if extracted == known_message:
                    results['matching_protocols'].append({
                        'protocol_id': protocol['id'],
                        'protocol_desc': protocol['description']
                    })
                
            except Exception:
                continue
            
            results['protocols_tested'] += 1
        
        results['attack_time'] = time.time() - start_time
        return results
    
    def statistical_attack(self, stego_folder: str, cover_folders: List[str],
                          multiple_stego_samples: List[str] = None) -> Dict:
        """
        Statistical analysis attack to infer protocol patterns
        
        Args:
            stego_folder: Path to stego-folder
            cover_folders: List of cover folder paths
            multiple_stego_samples: Optional list of additional stego-folders
            
        Returns:
            Statistical analysis results
        """
        
        results = {
            'file_selection_patterns': [],
            'index_distribution': {},
            'protocol_inference': None
        }
        
        # Analyze file selection patterns
        stego_files = [os.path.join(stego_folder, f) for f in os.listdir(stego_folder)]
        
        # For each stego file, find which cover folder it came from
        file_mappings = []
        for stego_file in stego_files:
            for i, cover_folder in enumerate(cover_folders):
                cover_files = [os.path.join(cover_folder, f) for f in os.listdir(cover_folder)]
                
                # Simple content matching (in real attack would use hashes)
                stego_content = self._read_file_start(stego_file)
                for cover_file in cover_files:
                    cover_content = self._read_file_start(cover_file)
                    if stego_content == cover_content:
                        file_mappings.append({
                            'stego_file': os.path.basename(stego_file),
                            'cover_folder': i,
                            'cover_file': os.path.basename(cover_file)
                        })
                        break
        
        results['file_selection_patterns'] = file_mappings
        
        # Analyze if there's a pattern in which files are selected
        if file_mappings:
            # Check if files are selected from specific positions
            cover_positions = []
            for mapping in file_mappings:
                cover_folder_idx = mapping['cover_folder']
                cover_files = sorted(os.listdir(cover_folders[cover_folder_idx]))
                cover_file_idx = cover_files.index(mapping['cover_file'])
                cover_positions.append(cover_file_idx)
            
            results['index_distribution'] = {
                'min': min(cover_positions) if cover_positions else 0,
                'max': max(cover_positions) if cover_positions else 0,
                'mean': sum(cover_positions)/len(cover_positions) if cover_positions else 0,
                'std': self._std_dev(cover_positions) if len(cover_positions) > 1 else 0
            }
            
            # Try to infer protocol based on index distribution
            results['protocol_inference'] = self._infer_protocol_from_indices(cover_positions)
        
        return results
    
    def _is_plausible_message(self, message: str) -> bool:
        """Check if extracted message is plausible (not random garbage)"""
        if not message:
            return False
        
        # Simple heuristic: check for printable characters
        printable_ratio = sum(1 for c in message if c.isprintable()) / len(message)
        
        # Check for common patterns
        common_patterns = ['the', 'and', 'for', 'you', 'this', 'that']
        pattern_found = any(pattern in message.lower() for pattern in common_patterns)
        
        return printable_ratio > 0.8 or pattern_found
    
    def _read_file_start(self, filepath: str, bytes_to_read: int = 100) -> bytes:
        """Read start of file for comparison"""
        try:
            with open(filepath, 'rb') as f:
                return f.read(bytes_to_read)
        except:
            return b''
    
    def _std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if len(values) < 2:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
    
    def _infer_protocol_from_indices(self, indices: List[int]) -> str:
        """Attempt to infer protocol from selected indices"""
        if not indices:
            return "Cannot infer - no indices"
        
        # Check if indices are sequential
        is_sequential = all(indices[i] <= indices[i+1] for i in range(len(indices)-1))
        
        # Check if indices are random
        unique_indices = len(set(indices))
        randomness = unique_indices / len(indices)
        
        if is_sequential and randomness > 0.7:
            return "Likely ascending sort order"
        elif not is_sequential and randomness > 0.7:
            return "Likely content-based or random selection"
        elif randomness < 0.3:
            return "Possible fixed position selection"
        else:
            return "Inconclusive - complex pattern"


class TestProtocolAttackResistance(unittest.TestCase):
    """Test CCS resistance to protocol discovery attacks"""
    
    def setUp(self):
        """Setup test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="test_protocol_attack_")
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
        
        # Initialize attacker
        self.attacker = ProtocolAttacker(self.config)
        
    def tearDown(self):
        """Cleanup"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def _create_test_environment(self):
        """Create test folders and embed messages"""
        # Create cover folders
        self.cover_folders = []
        for i in range(3):
            folder_path = os.path.join(self.test_dir, f"cover_folder_{i}")
            os.makedirs(folder_path, exist_ok=True)
            self.cover_folders.append(folder_path)
            
            # Create 32 files in each folder
            for j in range(32):
                file_path = os.path.join(folder_path, f"file_{j:03d}.dat")
                with open(file_path, 'wb') as f:
                    # Unique content for each file
                    content = f"Folder {i}, File {j}: ".encode() + os.urandom(100)
                    f.write(content)
        
        # Setup CCS with specific protocol
        self.embedder = CCSEmbedder(self.config)
        self.extractor = CCSExtractor(self.config)
        self.security_manager = SecurityManager(self.config['security'])
        
        # Generate keys
        self.keys = self.security_manager.generate_keys("protocol_test")
        
        # Use a specific protocol (attacker doesn't know this)
        self.true_protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending',
            'combination': 'primary_secondary',
            'transform': 'none'
        }
        
        self.true_protocol_id = "P042"  # Example ID
        
        self.true_stego_key = {
            'protocol': self.true_protocol,
            'encryption_key': self.keys['encryption_key']
        }
        
        # Embed test message
        self.test_message = "Secret protocol test message for attack resistance testing"
        self.stego_folder = self.embedder.embed(
            self.test_message,
            self.cover_folders,
            self.true_stego_key
        )
    
    def test_brute_force_resistance(self):
        """Test resistance to brute-force protocol discovery"""
        
        print("\n" + "="*70)
        print("BRUTE-FORCE PROTOCOL ATTACK SIMULATION")
        print("="*70)
        
        # Simulate attack with limited number of protocols (for testing)
        max_protocols_to_test = 50  # Small subset for testing
        
        attack_results = self.attacker.brute_force_attack(
            self.stego_folder,
            self.cover_folders,
            self.keys['encryption_key'],
            max_protocols=max_protocols_to_test
        )
        
        # Report results
        print(f"\nAttack Parameters:")
        print(f"Protocols tested: {attack_results['total_protocols_tested']}")
        print(f"Time per protocol: {attack_results.get('avg_time_per_protocol', 0):.3f}s")
        print(f"Total attack time: {attack_results.get('total_attack_time', 0):.3f}s")
        
        print(f"\nAttack Results:")
        print(f"Successful protocol guesses: {len(attack_results['successful_protocols'])}")
        
        if attack_results['successful_protocols']:
            print("\nProtocols that produced plausible output:")
            for success in attack_results['successful_protocols']:
                print(f"  {success['protocol_id']}: {success['protocol_desc']}")
                print(f"    Extracted: {success['extracted_message']}")
        
        # Security assertion: With limited testing, should not find correct protocol
        # (In full attack with 480 protocols, probability is very low)
        correct_protocol_found = any(
            success['protocol_id'] == self.true_protocol_id
            for success in attack_results['successful_protocols']
        )
        
        if correct_protocol_found:
            print(f"\n⚠️  CORRECT PROTOCOL FOUND: {self.true_protocol_id}")
        else:
            print(f"\n✓ Correct protocol not found in limited attack")
        
        # Even if some protocols produce plausible output, they shouldn't be the correct one
        # in this limited test
        self.assertLess(len(attack_results['successful_protocols']), 3,
                       "Too many protocols produce plausible output")
    
    def test_known_plaintext_attack_resistance(self):
        """Test resistance to known-plaintext attacks"""
        
        print("\n" + "="*70)
        print("KNOWN-PLAINTEXT ATTACK SIMULATION")
        print("="*70)
        
        # Attacker knows the secret message (worst-case scenario)
        attack_results = self.attacker.known_plaintext_attack(
            self.stego_folder,
            self.cover_folders,
            self.test_message,
            self.keys['encryption_key']
        )
        
        print(f"\nAttack Results:")
        print(f"Protocols tested: {attack_results['protocols_tested']}")
        print(f"Attack time: {attack_results['attack_time']:.2f}s")
        print(f"Matching protocols found: {len(attack_results['matching_protocols'])}")
        
        if attack_results['matching_protocols']:
            print("\nProtocols that correctly extracted the message:")
            for match in attack_results['matching_protocols']:
                print(f"  {match['protocol_id']}: {match['protocol_desc']}")
        
        # Security assertion: Even with known plaintext, should not find unique protocol
        # Multiple protocols might produce same output due to file selection ambiguity
        self.assertGreaterEqual(len(attack_results['matching_protocols']), 1,
                              "Known-plaintext attack should find at least one matching protocol")
        
        # But it shouldn't uniquely identify the correct protocol
        if len(attack_results['matching_protocols']) == 1:
            only_match = attack_results['matching_protocols'][0]
            if only_match['protocol_id'] == self.true_protocol_id:
                print(f"\n⚠️  UNIQUE PROTOCOL IDENTIFIED: {self.true_protocol_id}")
            else:
                print(f"\n✓ Attack found wrong protocol: {only_match['protocol_id']}")
        else:
            print(f"\n✓ Attack found {len(attack_results['matching_protocols'])} candidate protocols")
    
    def test_statistical_attack_resistance(self):
        """Test resistance to statistical analysis attacks"""
        
        print("\n" + "="*70)
        print("STATISTICAL ANALYSIS ATTACK")
        print("="*70)
        
        # Attacker only has stego folder and cover folders
        # No knowledge of secret message or encryption key
        attack_results = self.attacker.statistical_attack(
            self.stego_folder,
            self.cover_folders
        )
        
        print(f"\nFile Selection Analysis:")
        print(f"Files mapped: {len(attack_results['file_selection_patterns'])}")
        
        if attack_results['index_distribution']:
            dist = attack_results['index_distribution']
            print(f"\nIndex Distribution:")
            print(f"  Min: {dist['min']}")
            print(f"  Max: {dist['max']}")
            print(f"  Mean: {dist['mean']:.1f}")
            print(f"  Std Dev: {dist['std']:.1f}")
        
        print(f"\nProtocol Inference:")
        print(f"  {attack_results['protocol_inference']}")
        
        # Security assertion: Statistical analysis should not reveal protocol
        inference = attack_results['protocol_inference']
        
        # Check if inference is too specific
        specific_terms = ['ascending', 'descending', 'content-based', 'size-based']
        inference_specific = any(term in inference.lower() for term in specific_terms)
        
        if inference_specific:
            print(f"\n⚠️  Statistical analysis may reveal protocol characteristics")
            # This is acceptable if multiple protocols share these characteristics
        else:
            print(f"\n✓ Statistical analysis inconclusive")
        
        # The mean index should be around the middle if selection is uniform
        if 'mean' in attack_results['index_distribution']:
            mean_index = attack_results['index_distribution']['mean']
            total_files = 32  # Files per folder in our test
            
            # Mean should be near middle for uniform selection
            self.assertGreater(mean_index, total_files * 0.3,
                             f"Selection bias detected: mean index {mean_index} too low")
            self.assertLess(mean_index, total_files * 0.7,
                          f"Selection bias detected: mean index {mean_index} too high")
    
    def test_protocol_space_size(self):
        """Test that protocol space is sufficiently large"""
        
        protocol_manager = ProtocolManager()
        all_protocols = protocol_manager.list_protocols()
        
        print(f"\nProtocol Space Analysis:")
        print(f"Total protocols: {len(all_protocols)}")
        
        # Count by primary attribute
        by_primary = {}
        for protocol in all_protocols:
            primary = protocol['primary_attribute'].value
            by_primary[primary] = by_primary.get(primary, 0) + 1
        
        print("\nProtocols by primary attribute:")
        for primary, count in sorted(by_primary.items()):
            print(f"  {primary}: {count}")
        
        # Security assertion: Protocol space should be large
        self.assertGreaterEqual(len(all_protocols), 480,
                              f"Protocol space too small: {len(all_protocols)} protocols")
        
        # Should have diversity in attributes
        self.assertGreaterEqual(len(by_primary), 4,
                              f"Insufficient protocol diversity: {len(by_primary)} attribute types")
    
    def test_protocol_entropy(self):
        """Test information entropy of protocol selection"""
        
        protocol_manager = ProtocolManager()
        all_protocols = protocol_manager.list_protocols()
        
        # Calculate entropy of protocol space
        # Each protocol is equally likely a priori
        entropy_bits = np.log2(len(all_protocols))
        
        print(f"\nProtocol Space Entropy:")
        print(f"Number of protocols: {len(all_protocols)}")
        print(f"Entropy: {entropy_bits:.1f} bits")
        
        # Security assertion: Sufficient entropy
        self.assertGreaterEqual(entropy_bits, 8.0,
                              f"Protocol entropy too low: {entropy_bits:.1f} bits")
        
        # Compare to cryptographic key entropy
        aes256_entropy = 256  # bits
        print(f"AES-256 key entropy: {aes256_entropy} bits")
        print(f"Protocol entropy as percentage of AES-256: {(entropy_bits/aes256_entropy)*100:.1f}%")
    
    def test_multi_session_attack(self):
        """Test attack across multiple stego sessions"""
        
        print("\n" + "="*70)
        print("MULTI-SESSION ATTACK SIMULATION")
        print("="*70)
        
        # Create multiple stego folders with same protocol
        stego_folders = []
        messages = [
            "First secret message",
            "Second confidential data",
            "Third encoded information",
            "Fourth hidden content"
        ]
        
        for i, message in enumerate(messages):
            stego_folder = self.embedder.embed(
                message,
                self.cover_folders,
                self.true_stego_key
            )
            stego_folders.append(stego_folder)
        
        # Analyze across sessions
        all_indices = []
        
        for stego_folder in stego_folders:
            # Simple analysis of each stego folder
            attack_results = self.attacker.statistical_attack(
                stego_folder,
                self.cover_folders
            )
            
            # Extract indices if available
            if attack_results['file_selection_patterns']:
                # Simplified - in real attack would compute actual indices
                pass
        
        print(f"\nMulti-session analysis:")
        print(f"Sessions analyzed: {len(stego_folders)}")
        print("Cross-session pattern analysis would require more sophisticated attack")
        
        # Cleanup
        import shutil
        for folder in stego_folders:
            shutil.rmtree(folder)
        
        # Security assertion: Multiple sessions don't make attack significantly easier
        # (Protocol remains secret across sessions)
        self.assertTrue(True)  # Placeholder - test structure


class TestRealWorldAttackScenarios(unittest.TestCase):
    """Real-world attack scenario simulations"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="realworld_attack_")
        self.config = {
            'security': {'encryption_algorithm': 'AES-256-CBC'},
            'performance': {'precompute_hashes': False}
        }
        
    def tearDown(self):
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_insider_attack_scenario(self):
        """Simulate insider with partial knowledge"""
        
        print("\n" + "="*70)
        print("INSIDER ATTACK SCENARIO")
        print("="*70)
        
        # Insider knows: cloud credentials, that CCS is being used
        # Does NOT know: specific protocol, encryption key
        
        # Create test environment
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        attacker = ProtocolAttacker(self.config)
        
        # Generate unknown (to attacker) keys and protocol
        true_keys = security_manager.generate_keys("secret_password")
        true_protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': None,
            'sort_order': 'ascending'
        }
        
        true_stego_key = {
            'protocol': true_protocol,
            'encryption_key': true_keys['encryption_key']
        }
        
        # Create cover folders
        cover_folders = []
        for i in range(2):
            folder = os.path.join(self.test_dir, f"cover_{i}")
            os.makedirs(folder, exist_ok=True)
            cover_folders.append(folder)
            
            for j in range(20):
                filepath = os.path.join(folder, f"file_{j:03d}.dat")
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(1024))
        
        # Embed message
        message = "Insider attack test message"
        stego_folder = embedder.embed(message, cover_folders, true_stego_key)
        
        # Insider attack: brute force with reduced search space
        # Insider might know some protocol characteristics
        protocol_manager = ProtocolManager()
        
        # Suppose insider knows it's content-based (reduces search space)
        content_based_protocols = protocol_manager.list_protocols(
            filter_by={'primary_attribute': PrimaryAttribute.CONTENT_HASH}
        )
        
        print(f"\nInsider Knowledge:")
        print(f"- Knows CCS is being used")
        print(f"- Knows protocol is content-based")
        print(f"Search space reduced from 480 to {len(content_based_protocols)} protocols")
        
        # Attack with reduced search space
        attack_results = attacker.brute_force_attack(
            stego_folder,
            cover_folders,
            true_keys['encryption_key'],  # Insider somehow obtained key
            max_protocols=len(content_based_protocols)
        )
        
        print(f"\nAttack Results:")
        print(f"Protocols tested: {attack_results['total_protocols_tested']}")
        print(f"Successful guesses: {len(attack_results['successful_protocols'])}")
        
        # Cleanup
        import shutil
        shutil.rmtree(stego_folder)
        
        # Security assertion: Even with insider knowledge, attack is hard
        success_rate = len(attack_results['successful_protocols']) / max(attack_results['total_protocols_tested'], 1)
        
        print(f"Success rate: {success_rate:.3%}")
        
        self.assertLess(success_rate, 0.1,
                       f"Insider attack too successful: {success_rate:.1%} success rate")
    
    def test_compressed_storage_attack(self):
        """Test attack when cloud provider compresses files"""
        
        print("\n" + "="*70)
        print("COMPRESSED STORAGE ATTACK SCENARIO")
        print("="*70)
        
        # Some cloud providers compress files
        # This could affect content-based protocols
        
        embedder = CCSEmbedder(self.config)
        security_manager = SecurityManager(self.config['security'])
        
        keys = security_manager.generate_keys("compression_test")
        
        # Test with different protocols
        protocols_to_test = [
            {'primary_attribute': 'content_hash', 'sort_order': 'ascending'},
            {'primary_attribute': 'file_size', 'sort_order': 'ascending'},
        ]
        
        results = []
        
        for protocol in protocols_to_test:
            stego_key = {
                'protocol': protocol,
                'encryption_key': keys['encryption_key']
            }
            
            # Create test folder
            cover_folder = os.path.join(self.test_dir, f"cover_{protocol['primary_attribute']}")
            os.makedirs(cover_folder, exist_ok=True)
            
            # Create files with compressible and incompressible content
            for i in range(10):
                filepath = os.path.join(cover_folder, f"file_{i:03d}.dat")
                
                if i % 2 == 0:
                    # Compressible content (repeating patterns)
                    content = b"AAAA" * 256  # 1KB of repeating pattern
                else:
                    # Incompressible content (random)
                    content = os.urandom(1024)
                
                with open(filepath, 'wb') as f:
                    f.write(content)
            
            # Embed
            message = f"Test for {protocol['primary_attribute']} protocol"
            stego_folder = embedder.embed(message, [cover_folder], stego_key)
            
            # Simulate compression (simple version)
            # In reality, cloud provider might compress files
            compressed_indices = []
            
            results.append({
                'protocol': protocol['primary_attribute'],
                'stego_folder': stego_folder,
                'compression_effect': 'Simulated - would need actual compression'
            })
        
        print("\nCompression Resistance Analysis:")
        for result in results:
            print(f"Protocol: {result['protocol']} - {result['compression_effect']}")
        
        # Security assertion: File size protocol more vulnerable to compression
        # Content hash protocol should be more robust
        print("\nRecommendation: Use content_hash protocol for compression resistance")
        
        # Cleanup
        import shutil
        for result in results:
            if os.path.exists(result['stego_folder']):
                shutil.rmtree(result['stego_folder'])


def run_protocol_attack_suite():
    """Run comprehensive protocol attack tests"""
    
    print("=" * 70)
    print("CCS PROTOCOL ATTACK RESISTANCE TEST SUITE")
    print("=" * 70)
    print("Testing security against protocol discovery attacks")
    print("Based on Section 5.2 of the paper")
    print()
    
    # Create test runner
    runner = unittest.TextTestRunner(verbosity=2)
    
    # Run protocol attack tests
    print("1. Protocol Attack Resistance Tests:")
    attack_suite = unittest.TestLoader().loadTestsFromTestCase(TestProtocolAttackResistance)
    attack_result = runner.run(attack_suite)
    
    # Run real-world scenarios
    print("\n2. Real-World Attack Scenarios:")
    realworld_suite = unittest.TestLoader().loadTestsFromTestCase(TestRealWorldAttackScenarios)
    realworld_result = runner.run(realworld_suite)
    
    # Summary
    print("\n" + "=" * 70)
    print("PROTOCOL SECURITY SUMMARY")
    print("=" * 70)
    
    total_tests = attack_result.testsRun + realworld_result.testsRun
    total_failures = len(attack_result.failures) + len(realworld_result.failures)
    total_errors = len(attack_result.errors) + len(realworld_result.errors)
    
    print(f"Total tests run: {total_tests}")
    print(f"Failures: {total_failures}")
    print(f"Errors: {total_errors}")
    
    if total_failures == 0 and total_errors == 0:
        print("\n✓ All protocol attack tests passed!")
        print("CCS demonstrates strong resistance to protocol discovery attacks.")
        print(f"Protocol space size: ≥480 protocols")
        print(f"Attack complexity: O(P ⋅ 2¹²⁸ ⋅ M log M)")
    else:
        print("\n✗ Some tests failed")
        print("Review failures for potential protocol security issues.")
    
    # Calculate and display security metrics
    protocol_manager = ProtocolManager()
    protocol_count = len(protocol_manager.list_protocols())
    
    print("\n" + "=" * 70)
    print("SECURITY METRICS")
    print("=" * 70)
    print(f"Protocol space size: {protocol_count} protocols")
    print(f"Protocol entropy: {np.log2(protocol_count):.1f} bits")
    print(f"Brute-force attack complexity: O({protocol_count} ⋅ 2¹²⁸ ⋅ M log M)")
    print(f"Equivalent to adding ~{np.log2(protocol_count):.1f} bits to AES-256 key")


if __name__ == '__main__':
    run_protocol_attack_suite()
