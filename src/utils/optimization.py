# Optimization Module for CCS
# Implements precomputed hash maps and caching for performance optimization

import hashlib
import json
import time
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import pickle
import os
from functools import lru_cache

from ..core.security import SecurityManager

class OptimizationManager:
    """
    Manages optimizations for CCS operations
    Implements precomputed hash maps and caching strategies
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.security_manager = SecurityManager(config.get('security', {}))
        
        # Cache configuration
        self.cache_enabled = config.get('cache_enabled', True)
        self.cache_dir = config.get('cache_dir', '.ccs_cache')
        self.max_cache_size = config.get('max_cache_size', 100 * 1024 * 1024)  # 100MB
        
        # Performance configuration
        self.precompute_hashes = config.get('precompute_hashes', True)
        self.parallel_processing = config.get('parallel_processing', True)
        self.batch_size = config.get('batch_size', 100)
        
        # Initialize cache
        self._init_cache()
        
        # Statistics
        self.stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'precomputation_time': 0,
            'extraction_speedups': []
        }
    
    def _init_cache(self):
        """Initialize cache directory and structures"""
        if self.cache_enabled and not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
        
        # In-memory caches
        self.hash_cache = {}  # File content -> hash
        self.sorted_cache = {}  # Folder + protocol -> sorted list
        self.protocol_cache = {}  # Protocol definitions
        
        # Disk-backed cache for large data
        self.disk_cache_enabled = True
        self.disk_cache_file = os.path.join(self.cache_dir, 'optimization_cache.pkl')
        
        # Load existing cache if available
        self._load_disk_cache()
    
    def _load_disk_cache(self):
        """Load cache from disk"""
        if not self.disk_cache_enabled or not os.path.exists(self.disk_cache_file):
            return
        
        try:
            with open(self.disk_cache_file, 'rb') as f:
                disk_cache = pickle.load(f)
                
                # Update in-memory caches
                self.hash_cache.update(disk_cache.get('hash_cache', {}))
                self.sorted_cache.update(disk_cache.get('sorted_cache', {}))
                self.protocol_cache.update(disk_cache.get('protocol_cache', {}))
                
            print(f"Loaded cache from disk: {len(self.hash_cache)} hashes, "
                  f"{len(self.sorted_cache)} sorted lists")
        except Exception as e:
            print(f"Failed to load disk cache: {e}")
    
    def _save_disk_cache(self):
        """Save cache to disk"""
        if not self.disk_cache_enabled:
            return
        
        try:
            disk_cache = {
                'hash_cache': self.hash_cache,
                'sorted_cache': self.sorted_cache,
                'protocol_cache': self.protocol_cache,
                'timestamp': time.time()
            }
            
            with open(self.disk_cache_file, 'wb') as f:
                pickle.dump(disk_cache, f)
                
            print(f"Saved cache to disk: {len(self.hash_cache)} hashes, "
                  f"{len(self.sorted_cache)} sorted lists")
        except Exception as e:
            print(f"Failed to save disk cache: {e}")
    
    def precompute_folder_hashes(self, folder_path: str, protocol: Dict, 
                                encryption_key: bytes) -> Dict[str, int]:
        """
        Precompute hash map for a folder (Algorithm 2 optimization)
        
        Args:
            folder_path: Path to folder
            protocol: Contextual protocol
            encryption_key: Key for HMAC computation
            
        Returns:
            Dictionary mapping file hashes to indices
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = self._get_cache_key(folder_path, protocol, encryption_key)
        
        if cache_key in self.hash_cache:
            self.stats['cache_hits'] += 1
            return self.hash_cache[cache_key]
        
        self.stats['cache_misses'] += 1
        
        # Import here to avoid circular imports
        from ..core.embedding import CCSEmbedder
        
        # Get sorted file list
        embedder = CCSEmbedder(self.config)
        files = self._get_folder_files(folder_path)
        sorted_files = embedder.apply_protocol(files, protocol)
        
        # Precompute hash map
        hash_map = {}
        for idx, file_path in enumerate(sorted_files):
            try:
                # Compute HMAC of file content
                file_hash = self.security_manager.compute_hmac(
                    self._read_file_content(file_path),
                    encryption_key
                )
                hash_map[file_hash] = idx
            except Exception as e:
                print(f"Error computing hash for {file_path}: {e}")
                continue
        
        # Store in cache
        self.hash_cache[cache_key] = hash_map
        self.sorted_cache[cache_key] = sorted_files
        
        # Update statistics
        elapsed = time.time() - start_time
        self.stats['precomputation_time'] += elapsed
        
        print(f"Precomputed hashes for {folder_path}: "
              f"{len(hash_map)} files in {elapsed:.2f}s")
        
        return hash_map
    
    @lru_cache(maxsize=128)
    def get_sorted_file_list(self, folder_path: str, protocol: Dict) -> List[str]:
        """
        Get sorted file list with caching
        
        Args:
            folder_path: Path to folder
            protocol: Contextual protocol
            
        Returns:
            Sorted list of file paths
        """
        cache_key = f"sorted_{hash(folder_path)}_{hash(json.dumps(protocol, sort_keys=True))}"
        
        if cache_key in self.sorted_cache:
            return self.sorted_cache[cache_key]
        
        from ..core.embedding import CCSEmbedder
        embedder = CCSEmbedder(self.config)
        files = self._get_folder_files(folder_path)
        sorted_files = embedder.apply_protocol(files, protocol)
        
        self.sorted_cache[cache_key] = sorted_files
        return sorted_files
    
    def batch_precompute(self, folders: List[str], protocols: List[Dict], 
                        encryption_key: bytes, max_workers: int = 4) -> Dict:
        """
        Batch precompute hashes for multiple folders
        
        Args:
            folders: List of folder paths
            protocols: List of protocols (one per folder or same for all)
            encryption_key: Encryption key
            max_workers: Maximum parallel workers
            
        Returns:
            Dictionary of precomputed hash maps
        """
        results = {}
        
        if self.parallel_processing and len(folders) > 1:
            # Parallel processing
            import concurrent.futures
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_folder = {}
                
                for i, folder in enumerate(folders):
                    protocol = protocols[i] if len(protocols) > i else protocols[0]
                    future = executor.submit(
                        self.precompute_folder_hashes,
                        folder, protocol, encryption_key
                    )
                    future_to_folder[future] = (folder, protocol)
                
                for future in concurrent.futures.as_completed(future_to_folder):
                    folder, protocol = future_to_folder[future]
                    try:
                        hash_map = future.result()
                        cache_key = self._get_cache_key(folder, protocol, encryption_key)
                        results[cache_key] = hash_map
                    except Exception as e:
                        print(f"Error precomputing {folder}: {e}")
        else:
            # Sequential processing
            for i, folder in enumerate(folders):
                protocol = protocols[i] if len(protocols) > i else protocols[0]
                hash_map = self.precompute_folder_hashes(folder, protocol, encryption_key)
                cache_key = self._get_cache_key(folder, protocol, encryption_key)
                results[cache_key] = hash_map
        
        return results
    
    def optimized_extraction(self, stego_folder: str, hash_maps: Dict, 
                           encryption_key: bytes) -> List[Tuple[int, int]]:
        """
        Optimized extraction using precomputed hash maps
        
        Args:
            stego_folder: Path to stego-folder
            hash_maps: Dictionary of precomputed hash maps
            encryption_key: Encryption key
            
        Returns:
            List of (folder_index, file_index) tuples
        """
        start_time = time.time()
        
        # Get stego files
        stego_files = self._get_folder_files(stego_folder)
        indices = []
        
        for stego_file in stego_files:
            try:
                # Compute HMAC of stego file
                stego_content = self._read_file_content(stego_file)
                stego_hash = self.security_manager.compute_hmac(stego_content, encryption_key)
                
                # Search in hash maps
                found = False
                for cache_key, hash_map in hash_maps.items():
                    if stego_hash in hash_map:
                        # Parse cache key to get folder index
                        # cache_key format: "folder_path|protocol_hash|key_hash"
                        parts = cache_key.split('|')
                        folder_idx = int(parts[0].split('_')[-1]) if '_' in parts[0] else 0
                        file_idx = hash_map[stego_hash]
                        
                        indices.append((folder_idx, file_idx))
                        found = True
                        break
                
                if not found:
                    print(f"Warning: Stego file {stego_file} not found in any hash map")
                    
            except Exception as e:
                print(f"Error processing stego file {stego_file}: {e}")
                continue
        
        # Record speedup
        elapsed = time.time() - start_time
        speedup = len(stego_files) / max(elapsed, 0.001)  # Files per second
        self.stats['extraction_speedups'].append(speedup)
        
        print(f"Optimized extraction: {len(indices)} files in {elapsed:.3f}s "
              f"({speedup:.1f} files/sec)")
        
        return indices
    
    def clear_cache(self, cache_type: str = None):
        """
        Clear cache
        
        Args:
            cache_type: Type of cache to clear (None for all)
        """
        if cache_type is None or cache_type == 'hash':
            self.hash_cache.clear()
        if cache_type is None or cache_type == 'sorted':
            self.sorted_cache.clear()
        if cache_type is None or cache_type == 'protocol':
            self.protocol_cache.clear()
        
        print(f"Cache cleared: {cache_type or 'all'}")
    
    def get_statistics(self) -> Dict:
        """
        Get optimization statistics
        
        Returns:
            Dictionary with statistics
        """
        avg_speedup = (sum(self.stats['extraction_speedups']) / 
                      len(self.stats['extraction_speedups']) 
                      if self.stats['extraction_speedups'] else 0)
        
        return {
            'cache_hits': self.stats['cache_hits'],
            'cache_misses': self.stats['cache_misses'],
            'cache_hit_ratio': (self.stats['cache_hits'] / 
                               max(self.stats['cache_hits'] + self.stats['cache_misses'], 1)),
            'precomputation_time_total': self.stats['precomputation_time'],
            'extraction_speedup_avg': avg_speedup,
            'hash_cache_size': len(self.hash_cache),
            'sorted_cache_size': len(self.sorted_cache),
            'protocol_cache_size': len(self.protocol_cache)
        }
    
    def _get_cache_key(self, folder_path: str, protocol: Dict, 
                      encryption_key: bytes) -> str:
        """Generate cache key for folder, protocol, and key combination"""
        protocol_hash = hashlib.sha256(
            json.dumps(protocol, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        key_hash = hashlib.sha256(encryption_key).hexdigest()[:16]
        
        return f"{folder_path}|{protocol_hash}|{key_hash}"
    
    def _get_folder_files(self, folder_path: str) -> List[str]:
        """Get list of files in folder"""
        if not os.path.exists(folder_path):
            return []
        
        files = []
        for item in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item)
            if os.path.isfile(item_path):
                files.append(item_path)
        
        return files
    
    def _read_file_content(self, file_path: str) -> bytes:
        """Read file content with caching"""
        cache_key = f"content_{file_path}_{os.path.getmtime(file_path)}"
        
        if cache_key in self.hash_cache:
            return self.hash_cache[cache_key]
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        self.hash_cache[cache_key] = content
        return content


class MemoryOptimizer:
    """Optimizes memory usage for large operations"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.memory_limit = config.get('memory_limit_mb', 512) * 1024 * 1024
        
    def optimize_memory_usage(self, operation: str, data_size: int) -> Dict:
        """
        Optimize memory usage for operation
        
        Args:
            operation: Operation type ('embedding', 'extraction', 'precomputation')
            data_size: Estimated data size in bytes
            
        Returns:
            Optimization parameters
        """
        import psutil
        
        available_memory = psutil.virtual_memory().available
        optimization = {
            'batch_size': self.config.get('batch_size', 100),
            'use_disk_cache': False,
            'stream_processing': False,
            'compression': False
        }
        
        # Adjust based on available memory
        if data_size > available_memory * 0.5:  # Would use more than 50% of available memory
            optimization['use_disk_cache'] = True
            optimization['batch_size'] = max(10, optimization['batch_size'] // 2)
            
            if data_size > available_memory:
                optimization['stream_processing'] = True
                optimization['compression'] = True
        
        # Operation-specific optimizations
        if operation == 'extraction':
            optimization['batch_size'] = min(optimization['batch_size'], 50)
        
        return optimization


class PerformanceMonitor:
    """Monitors and optimizes performance"""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self.thresholds = {
            'extraction_time': 5.0,  # seconds
            'embedding_time': 10.0,  # seconds
            'memory_usage': 0.8,  # 80% of available
            'cache_hit_ratio': 0.7  # 70%
        }
    
    def record_metric(self, metric: str, value: float):
        """Record performance metric"""
        self.metrics[metric].append(value)
        
        # Keep only last 100 measurements
        if len(self.metrics[metric]) > 100:
            self.metrics[metric] = self.metrics[metric][-100:]
    
    def check_thresholds(self) -> Dict[str, bool]:
        """
        Check if metrics exceed thresholds
        
        Returns:
            Dictionary of threshold violations
        """
        violations = {}
        
        for metric, threshold in self.thresholds.items():
            if metric in self.metrics and self.metrics[metric]:
                avg_value = sum(self.metrics[metric]) / len(self.metrics[metric])
                violations[metric] = avg_value > threshold
        
        return violations
    
    def get_recommendations(self) -> List[str]:
        """
        Get optimization recommendations based on metrics
        
        Returns:
            List of recommendation strings
        """
        recommendations = []
        violations = self.check_thresholds()
        
        if violations.get('extraction_time', False):
            recommendations.append(
                "Extraction time high: Consider enabling precomputed hash maps"
            )
        
        if violations.get('embedding_time', False):
            recommendations.append(
                "Embedding time high: Consider reducing folder sizes or "
                "using simpler protocols"
            )
        
        if violations.get('memory_usage', False):
            recommendations.append(
                "Memory usage high: Enable disk caching and reduce batch size"
            )
        
        if not violations.get('cache_hit_ratio', True):
            recommendations.append(
                "Cache hit ratio low: Consider increasing cache size or "
                "using more specific cache keys"
            )
        
        return recommendations
    
    def generate_report(self) -> Dict:
        """
        Generate performance report
        
        Returns:
            Dictionary with performance metrics
        """
        report = {}
        
        for metric, values in self.metrics.items():
            if values:
                report[metric] = {
                    'avg': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'last_10_avg': sum(values[-10:]) / min(len(values), 10),
                    'count': len(values)
                }
        
        report['threshold_violations'] = self.check_thresholds()
        report['recommendations'] = self.get_recommendations()
        
        return report
