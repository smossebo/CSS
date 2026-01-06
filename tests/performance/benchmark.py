# !/usr/bin/env python3
# Performance Benchmark Tests
# Measures embedding/extraction times for different folder sizes


import os
import tempfile
import time
import statistics
import hashlib
import json
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.embedding import CCSEmbedder
from src.core.extraction import CCSExtractor

class PerformanceBenchmark:
    """Benchmark CCS performance across different folder sizes"""
    
    def __init__(self):
        self.config = {
            'security': {
                'encryption_algorithm': 'AES-256-CBC',
                'hmac_algorithm': 'SHA256'
            },
            'performance': {
                'precompute_hashes': True,
                'cache_sorted_lists': True
            }
        }
        
        self.results = {
            'embedding_times': [],
            'extraction_times': [],
            'optimized_extraction_times': [],
            'capacity_measurements': []
        }
    
    def create_test_folder(self, num_files: int, avg_size_kb: int = 100) -> str:
        """Create test folder with specified number of files"""
        folder_path = tempfile.mkdtemp(prefix=f"benchmark_{num_files}_")
        
        for i in range(num_files):
            file_name = f"file_{i:06d}.dat"
            file_path = os.path.join(folder_path, file_name)
            
            # Create file with random content
            file_size = avg_size_kb * 1024
            content = os.urandom(file_size)
            
            with open(file_path, 'wb') as f:
                f.write(content)
        
        print(f"Created folder with {num_files} files ({avg_size_kb}KB avg)")
        return folder_path
    
    def benchmark_embedding(self, folder_sizes: List[int], iterations: int = 5):
        """Benchmark embedding performance"""
        print("\n" + "="*60)
        print("EMBEDDING PERFORMANCE BENCHMARK")
        print("="*60)
        
        for num_files in folder_sizes:
            print(f"\nBenchmarking with {num_files} files:")
            
            times = []
            capacities = []
            
            for iteration in range(iterations):
                # Create test folder
                folder_path = self.create_test_folder(num_files)
                
                # Create embedder
                embedder = CCSEmbedder(self.config)
                
                # Prepare test data
                secret_message = "Test secret message " * 10  # ~200 chars
                stego_key = {
                    'protocol': {
                        'primary_attribute': 'content_hash',
                        'secondary_attribute': 'file_size',
                        'sort_order': 'ascending'
                    },
                    'encryption_key': hashlib.sha256(b"benchmark_key").digest()
                }
                
                # Measure embedding time
                start_time = time.perf_counter()
                stego_folder = embedder.embed(
                    secret_message,
                    [folder_path],
                    stego_key
                )
                end_time = time.perf_counter()
                
                embedding_time = end_time - start_time
                times.append(embedding_time)
                
                # Calculate capacity
                capacity_bits = (num_files.bit_length() - 1)
                capacities.append(capacity_bits)
                
                # Cleanup
                import shutil
                shutil.rmtree(folder_path)
                if os.path.exists(stego_folder):
                    shutil.rmtree(stego_folder)
                
                print(f"  Iteration {iteration + 1}: {embedding_time:.3f}s, "
                      f"Capacity: {capacity_bits} bits")
            
            # Calculate statistics
            avg_time = statistics.mean(times)
            std_time = statistics.stdev(times) if len(times) > 1 else 0
            avg_capacity = statistics.mean(capacities)
            
            self.results['embedding_times'].append({
                'num_files': num_files,
                'avg_time': avg_time,
                'std_time': std_time,
                'iterations': iterations
            })
            
            self.results['capacity_measurements'].append({
                'num_files': num_files,
                'capacity_bits': avg_capacity,
                'theoretical_bits': num_files.bit_length() - 1
            })
            
            print(f"  Average: {avg_time:.3f}s ± {std_time:.3f}s")
    
    def benchmark_extraction(self, folder_sizes: List[int], iterations: int = 5):
        """Benchmark extraction performance"""
        print("\n" + "="*60)
        print("EXTRACTION PERFORMANCE BENCHMARK")
        print("="*60)
        
        for num_files in folder_sizes:
            print(f"\nBenchmarking with {num_files} files:")
            
            standard_times = []
            optimized_times = []
            
            for iteration in range(iterations):
                # Create test folder
                folder_path = self.create_test_folder(num_files)
                
                # Create embedder and extractor
                embedder = CCSEmbedder(self.config)
                extractor = CCSExtractor(self.config)
                
                # Prepare test data
                secret_message = "Extraction test " * 10
                stego_key = {
                    'protocol': {
                        'primary_attribute': 'content_hash',
                        'secondary_attribute': 'file_size',
                        'sort_order': 'ascending'
                    },
                    'encryption_key': hashlib.sha256(b"extraction_key").digest()
                }
                
                # Embed message first
                stego_folder = embedder.embed(
                    secret_message,
                    [folder_path],
                    stego_key
                )
                
                # Benchmark standard extraction
                start_time = time.perf_counter()
                extracted = extractor.extract(stego_folder, [folder_path], stego_key)
                end_time = time.perf_counter()
                
                standard_time = end_time - start_time
                standard_times.append(standard_time)
                
                # Verify extraction
                if extracted != secret_message:
                    print(f"  WARNING: Extraction verification failed!")
                
                # Benchmark with precomputation (second extraction)
                start_time = time.perf_counter()
                extracted = extractor.extract(stego_folder, [folder_path], stego_key)
                end_time = time.perf_counter()
                
                optimized_time = end_time - start_time
                optimized_times.append(optimized_time)
                
                # Cleanup
                import shutil
                shutil.rmtree(folder_path)
                if os.path.exists(stego_folder):
                    shutil.rmtree(stego_folder)
                
                print(f"  Iteration {iteration + 1}: "
                      f"Standard: {standard_time:.3f}s, "
                      f"Optimized: {optimized_time:.3f}s")
            
            # Calculate statistics
            avg_standard = statistics.mean(standard_times)
            std_standard = statistics.stdev(standard_times) if len(standard_times) > 1 else 0
            
            avg_optimized = statistics.mean(optimized_times)
            std_optimized = statistics.stdev(optimized_times) if len(optimized_times) > 1 else 0
            
            self.results['extraction_times'].append({
                'num_files': num_files,
                'avg_time': avg_standard,
                'std_time': std_standard,
                'iterations': iterations
            })
            
            self.results['optimized_extraction_times'].append({
                'num_files': num_files,
                'avg_time': avg_optimized,
                'std_time': std_optimized,
                'iterations': iterations
            })
            
            improvement = ((avg_standard - avg_optimized) / avg_standard * 100) if avg_standard > 0 else 0
            
            print(f"  Standard: {avg_standard:.3f}s ± {std_standard:.3f}s")
            print(f"  Optimized: {avg_optimized:.3f}s ± {std_optimized:.3f}s")
            print(f"  Improvement: {improvement:.1f}%")
    
    def generate_report(self, output_file: str = "performance_report.json"):
        """Generate JSON performance report"""
        print("\n" + "="*60)
        print("GENERATING PERFORMANCE REPORT")
        print("="*60)
        
        # Calculate derived metrics
        for i, embedding_result in enumerate(self.results['embedding_times']):
            num_files = embedding_result['num_files']
            
            # Find corresponding extraction results
            extraction_result = next(
                (r for r in self.results['extraction_times'] 
                 if r['num_files'] == num_files),
                None
            )
            
            optimized_result = next(
                (r for r in self.results['optimized_extraction_times'] 
                 if r['num_files'] == num_files),
                None
            )
            
            capacity_result = next(
                (r for r in self.results['capacity_measurements'] 
                 if r['num_files'] == num_files),
                None
            )
            
            if all([extraction_result, optimized_result, capacity_result]):
                # Calculate total operation time
                total_time = embedding_result['avg_time'] + extraction_result['avg_time']
                total_optimized = embedding_result['avg_time'] + optimized_result['avg_time']
                
                # Add to results
                self.results['embedding_times'][i]['total_with_standard'] = total_time
                self.results['embedding_times'][i]['total_with_optimized'] = total_optimized
                
                # Calculate bits per second
                if embedding_result['avg_time'] > 0:
                    bits_per_second = capacity_result['capacity_bits'] / embedding_result['avg_time']
                    self.results['embedding_times'][i]['bits_per_second'] = bits_per_second
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nReport saved to {output_file}")
        
        # Print summary table
        self._print_summary_table()
    
    def _print_summary_table(self):
        """Print summary table of results"""
        print("\n" + "="*60)
        print("PERFORMANCE SUMMARY")
        print("="*60)
        print("\nFolder Size | Embed Time | Std Time | Opt Time | Capacity")
        print("-" * 60)
        
        for emb_result in sorted(self.results['embedding_times'], key=lambda x: x['num_files']):
            num_files = emb_result['num_files']
            
            # Get capacity
            cap_result = next(
                (r for r in self.results['capacity_measurements'] 
                 if r['num_files'] == num_files),
                {'capacity_bits': 0}
            )
            
            # Get optimized extraction time
            opt_result = next(
                (r for r in self.results['optimized_extraction_times'] 
                 if r['num_files'] == num_files),
                {'avg_time': 0}
            )
            
            print(f"{num_files:>10} | "
                  f"{emb_result['avg_time']:>10.3f}s | "
                  f"{emb_result['std_time']:>8.3f}s | "
                  f"{opt_result['avg_time']:>8.3f}s | "
                  f"{cap_result['capacity_bits']:>8} bits")


def main():
    """Main benchmark function"""
    benchmark = PerformanceBenchmark()
    
    # Test folder sizes from the paper
    folder_sizes = [64, 128, 256, 512, 1024, 2048, 4096]
    
    print("Starting CCS Performance Benchmark")
    print(f"Testing folder sizes: {folder_sizes}")
    
    # Run benchmarks
    benchmark.benchmark_embedding(folder_sizes, iterations=3)
    benchmark.benchmark_extraction(folder_sizes, iterations=3)
    
    # Generate report
    benchmark.generate_report()
    
    print("\n" + "="*60)
    print("BENCHMARK COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
