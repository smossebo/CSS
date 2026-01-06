import hashlib
import time
import threading
from typing import List, Dict, Optional, Callable
import logging
from enum import Enum

class ChangeLevel(Enum):
    NO_CHANGE = 0
    WARNING_CHANGE = 1
    CRITICAL_CHANGE = 2

class FolderMonitor:
    """
    Proactive Change Detection and Mitigation (Algorithm 7)
    Monitors folder stability in real-time
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.monitoring_threads = {}
        self.stop_monitoring = threading.Event()
        
        # Thresholds from configuration
        self.warning_threshold = config.get('warning_threshold', 0.1)  # 10% change
        self.critical_threshold = config.get('critical_threshold', 0.3)  # 30% change
        self.check_interval = config.get('check_interval', 60)  # Check every 60 seconds
        
    def compute_folder_hash(self, folder_path: str, protocol: Dict) -> str:
        """Compute cryptographic hash of sorted folder state"""
        from ..core.embedding import CCSEmbedder
        
        embedder = CCSEmbedder(self.config)
        files = self._get_folder_files(folder_path)
        
        if not files:
            return ""
        
        # Apply protocol to get deterministic ordering
        sorted_files = embedder.apply_protocol(files, protocol)
        
        # Compute hash of sorted file list
        hash_input = ""
        for file_path in sorted_files:
            # Use file metadata for hash, not content (for performance)
            stat = os.stat(file_path)
            hash_input += f"{file_path}:{stat.st_size}:{stat.st_mtime}:"
        
        return hashlib.sha256(hash_input.encode()).hexdigest()
    
    def compute_changes(self, old_list: List[str], new_list: List[str]) -> float:
        """Compute percentage of changes between two file lists"""
        old_set = set(old_list)
        new_set = set(new_list)
        
        # Files added or removed
        changed_files = old_set.symmetric_difference(new_set)
        
        # Also check for files that might have been modified (same name, different content)
        common_files = old_set.intersection(new_set)
        for file in common_files:
            try:
                old_stat = os.stat(os.path.join(self.current_folder, file))
                new_stat = os.stat(os.path.join(self.current_folder, file))
                if old_stat.st_mtime != new_stat.st_mtime or old_stat.st_size != new_stat.st_size:
                    changed_files.add(file)
            except:
                changed_files.add(file)
        
        change_ratio = len(changed_files) / max(len(old_set), 1)
        return change_ratio
    
    def monitor_folder_stability(self, folder_path: str, protocol: Dict,
                               callback: Optional[Callable] = None) -> threading.Thread:
        """
        Monitor folder stability continuously
        Returns a thread that can be stopped
        """
        
        def monitoring_loop():
            self.logger.info(f"Starting monitoring for {folder_path}")
            
            # Get initial state
            current_files = self._get_folder_files(folder_path)
            current_hash = self.compute_folder_hash(folder_path, protocol)
            
            while not self.stop_monitoring.is_set():
                try:
                    # Get new state
                    new_files = self._get_folder_files(folder_path)
                    new_hash = self.compute_folder_hash(folder_path, protocol)
                    
                    # Check for changes
                    if current_hash != new_hash:
                        change_ratio = self.compute_changes(
                            [os.path.basename(f) for f in current_files],
                            [os.path.basename(f) for f in new_files]
                        )
                        
                        # Determine change level
                        if change_ratio > self.critical_threshold:
                            change_level = ChangeLevel.CRITICAL_CHANGE
                            self.logger.warning(
                                f"CRITICAL change detected in {folder_path}: "
                                f"{change_ratio:.1%} of files changed"
                            )
                        elif change_ratio > self.warning_threshold:
                            change_level = ChangeLevel.WARNING_CHANGE
                            self.logger.info(
                                f"Warning: {change_ratio:.1%} change in {folder_path}"
                            )
                        else:
                            change_level = ChangeLevel.NO_CHANGE
                        
                        # Update state
                        current_files = new_files
                        current_hash = new_hash
                        
                        # Call callback if provided
                        if callback:
                            callback(folder_path, change_level, change_ratio)
                    
                    # Wait for next check
                    time.sleep(self.check_interval)
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop for {folder_path}: {e}")
                    time.sleep(self.check_interval * 2)  # Longer wait on error
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        
        # Store thread reference
        self.monitoring_threads[folder_path] = monitor_thread
        return monitor_thread
    
    def stop_monitoring_folder(self, folder_path: str):
        """Stop monitoring a specific folder"""
        self.stop_monitoring.set()
        if folder_path in self.monitoring_threads:
            self.monitoring_threads[folder_path].join(timeout=5)
            del self.monitoring_threads[folder_path]
    
    def stop_all_monitoring(self):
        """Stop all monitoring threads"""
        self.stop_monitoring.set()
        for folder_path, thread in self.monitoring_threads.items():
            thread.join(timeout=5)
        self.monitoring_threads.clear()
        self.stop_monitoring.clear()
    
    def _get_folder_files(self, folder_path: str) -> List[str]:
        """Get list of files in folder (excluding subdirectories)"""
        if not os.path.exists(folder_path):
            return []
        
        files = []
        for item in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item)
            if os.path.isfile(item_path):
                files.append(item_path)
        
        return files


# Example callback function
def change_callback(folder_path: str, change_level: ChangeLevel, change_ratio: float):
    """Example callback for handling detected changes"""
    actions = {
        ChangeLevel.CRITICAL_CHANGE: "Immediate extraction recommended",
        ChangeLevel.WARNING_CHANGE: "Monitor closely, consider extraction",
        ChangeLevel.NO_CHANGE: "No action needed"
    }
    
    print(f"Change in {folder_path}: {change_ratio:.1%} - {actions[change_level]}")
    
    if change_level == ChangeLevel.CRITICAL_CHANGE:
        # Trigger immediate backup or extraction
        trigger_emergency_extraction(folder_path)


def trigger_emergency_extraction(folder_path: str):
    """Trigger emergency extraction when critical changes detected"""
    print(f"EMERGENCY: Triggering extraction for {folder_path}")
    # Implementation would call CCS extraction immediately
