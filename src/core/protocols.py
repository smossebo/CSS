# Contextual Protocol Management
# Implements the 480+ protocol combinations from Table 4

from enum import Enum
from typing import List, Dict, Any, Callable
import hashlib
import os
import time

class PrimaryAttribute(Enum):
    CONTENT_HASH = "content_hash"
    FILE_SIZE = "file_size"
    TIMESTAMP = "timestamp"
    FILENAME = "filename"
    COMPOSITE = "composite"

class SortOrder(Enum):
    ASCENDING = "ascending"
    DESCENDING = "descending"

class ProtocolManager:
    """Manages the 480+ contextual protocol combinations"""
    
    def __init__(self):
        self.protocols = {}
        self._initialize_protocols()
    
    def _initialize_protocols(self):
        """Initialize all 480+ protocol combinations"""
        
        # Primary attributes (5 options)
        primary_attrs = [
            PrimaryAttribute.CONTENT_HASH,
            PrimaryAttribute.FILE_SIZE,
            PrimaryAttribute.TIMESTAMP,
            PrimaryAttribute.FILENAME,
            PrimaryAttribute.COMPOSITE
        ]
        
        # Secondary attributes (4 options for tie-breaking)
        secondary_attrs = [
            None,  # No secondary attribute
            PrimaryAttribute.FILE_SIZE,
            PrimaryAttribute.TIMESTAMP,
            PrimaryAttribute.FILENAME
        ]
        
        # Sort orders (2 options)
        sort_orders = [SortOrder.ASCENDING, SortOrder.DESCENDING]
        
        # Attribute combinations (3 options)
        combos = ["single", "primary_secondary", "weighted_composite"]
        
        # Custom transformations (4+ options)
        transforms = [
            "none",
            "bit_reverse",
            "byte_swap",
            "custom_hash"
        ]
        
        # Generate all combinations
        protocol_id = 0
        for primary in primary_attrs:
            for secondary in secondary_attrs:
                for order in sort_orders:
                    for combo in combos:
                        for transform in transforms:
                            protocol = {
                                'id': f"P{protocol_id:03d}",
                                'primary_attribute': primary,
                                'secondary_attribute': secondary,
                                'sort_order': order,
                                'combination': combo,
                                'transform': transform,
                                'description': self._generate_description(
                                    primary, secondary, order, combo, transform
                                )
                            }
                            self.protocols[protocol['id']] = protocol
                            protocol_id += 1
        
        print(f"Initialized {len(self.protocols)} protocol combinations")
    
    def _generate_description(self, primary, secondary, order, combo, transform):
        """Generate human-readable protocol description"""
        desc = f"Sort by {primary.value}"
        
        if secondary:
            desc += f", then by {secondary.value}"
        
        desc += f" ({order.value})"
        
        if combo != "single":
            desc += f" using {combo} combination"
        
        if transform != "none":
            desc += f" with {transform} transform"
        
        return desc
    
    def get_protocol(self, protocol_id: str) -> Dict:
        """Get protocol by ID"""
        return self.protocols.get(protocol_id)
    
    def list_protocols(self, filter_by: Dict = None) -> List[Dict]:
        """List all protocols, optionally filtered"""
        protocols = list(self.protocols.values())
        
        if filter_by:
            filtered = []
            for protocol in protocols:
                match = True
                for key, value in filter_by.items():
                    if protocol.get(key) != value:
                        match = False
                        break
                if match:
                    filtered.append(protocol)
            return filtered
        
        return protocols
    
    def sort_files(self, files: List[str], protocol: Dict) -> List[str]:
        """Sort files according to protocol specification"""
        
        # Apply custom transformation if specified
        if protocol['transform'] != 'none':
            files = self._apply_transform(files, protocol['transform'])
        
        # Get sorting key function based on protocol
        key_func = self._get_key_function(protocol)
        
        # Sort files
        sorted_files = sorted(files, key=key_func)
        
        # Apply sort order
        if protocol['sort_order'] == SortOrder.DESCENDING:
            sorted_files = list(reversed(sorted_files))
        
        return sorted_files
    
    def _get_key_function(self, protocol: Dict) -> Callable:
        """Get key function for sorting based on protocol"""
        primary = protocol['primary_attribute']
        secondary = protocol['secondary_attribute']
        combo = protocol['combination']
        
        if combo == "weighted_composite":
            # Weighted combination of multiple attributes
            return lambda f: self._weighted_composite_key(f, protocol)
        
        elif combo == "primary_secondary":
            # Primary then secondary
            return lambda f: (
                self._get_attribute_value(f, primary),
                self._get_attribute_value(f, secondary) if secondary else None
            )
        
        else:  # "single"
            # Single attribute
            return lambda f: self._get_attribute_value(f, primary)
    
    def _get_attribute_value(self, file_path: str, attribute: PrimaryAttribute) -> Any:
        """Get value of specified attribute for a file"""
        try:
            if attribute == PrimaryAttribute.CONTENT_HASH:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    return hashlib.sha256(content).hexdigest()
            
            elif attribute == PrimaryAttribute.FILE_SIZE:
                return os.path.getsize(file_path)
            
            elif attribute == PrimaryAttribute.TIMESTAMP:
                return os.path.getmtime(file_path)
            
            elif attribute == PrimaryAttribute.FILENAME:
                return os.path.basename(file_path).lower()
            
            elif attribute == PrimaryAttribute.COMPOSITE:
                # Composite of multiple attributes
                stat = os.stat(file_path)
                composite = f"{stat.st_size}:{stat.st_mtime}:{os.path.basename(file_path)}"
                return hashlib.sha256(composite.encode()).hexdigest()
            
        except Exception as e:
            # Return a default value if file cannot be accessed
            return ""
    
    def _weighted_composite_key(self, file_path: str, protocol: Dict) -> float:
        """Compute weighted composite key for file"""
        weights = {
            PrimaryAttribute.FILE_SIZE: 0.4,
            PrimaryAttribute.TIMESTAMP: 0.3,
            PrimaryAttribute.FILENAME: 0.3
        }
        
        composite = 0
        for attr, weight in weights.items():
            value = self._get_attribute_value(file_path, attr)
            
            # Normalize value to 0-1 range
            if isinstance(value, (int, float)):
                # Simple normalization (in practice would be more sophisticated)
                normalized = min(value / 1e9, 1.0)  # Cap at 1GB for size
            else:
                # For string values, use hash
                normalized = hash(str(value)) % 1000 / 1000
            
            composite += weight * normalized
        
        return composite
    
    def _apply_transform(self, files: List[str], transform: str) -> List[str]:
        """Apply custom transformation to file list"""
        if transform == "bit_reverse":
            # Sort by bit-reversed hash
            return sorted(files, key=lambda f: self._bit_reverse_hash(f))
        
        elif transform == "byte_swap":
            # Sort by byte-swapped hash
            return sorted(files, key=lambda f: self._byte_swap_hash(f))
        
        elif transform == "custom_hash":
            # Sort by custom hash function
            return sorted(files, key=lambda f: self._custom_hash(f))
        
        return files
    
    def _bit_reverse_hash(self, file_path: str) -> str:
        """Compute bit-reversed SHA-256 hash"""
        with open(file_path, 'rb') as f:
            content = f.read()
            hash_val = hashlib.sha256(content).hexdigest()
            
            # Convert to binary, reverse bits, convert back to hex
            binary = bin(int(hash_val, 16))[2:].zfill(256)
            reversed_binary = binary[::-1]
            reversed_hex = hex(int(reversed_binary, 2))[2:].zfill(64)
            
            return reversed_hex
    
    def _byte_swap_hash(self, file_path: str) -> str:
        """Compute byte-swapped SHA-256 hash"""
        with open(file_path, 'rb') as f:
            content = f.read()
            hash_val = hashlib.sha256(content).hexdigest()
            
            # Swap bytes (pairwise)
            bytes_list = [hash_val[i:i+2] for i in range(0, len(hash_val), 2)]
            swapped = []
            for i in range(0, len(bytes_list), 2):
                if i + 1 < len(bytes_list):
                    swapped.extend([bytes_list[i+1], bytes_list[i]])
                else:
                    swapped.append(bytes_list[i])
            
            return ''.join(swapped)
    
    def _custom_hash(self, file_path: str) -> str:
        """Custom hash function combining multiple attributes"""
        try:
            stat = os.stat(file_path)
            
            # Combine multiple attributes
            combined = f"{stat.st_size}:{stat.st_mtime}:{os.path.basename(file_path)}"
            
            # Apply multiple hash rounds
            hash_val = hashlib.sha256(combined.encode()).hexdigest()
            for _ in range(10):
                hash_val = hashlib.sha256(hash_val.encode()).hexdigest()
            
            return hash_val
        except:
            return "0" * 64


# Example usage
if __name__ == "__main__":
    manager = ProtocolManager()
    
    # List first 10 protocols
    print("First 10 protocol combinations:")
    for protocol in manager.list_protocols()[:10]:
        print(f"{protocol['id']}: {protocol['description']}")
    
    # Get specific protocol
    protocol_p123 = manager.get_protocol("P123")
    print(f"\nProtocol P123: {protocol_p123['description']}")
    
    # Filter protocols
    content_hash_protocols = manager.list_protocols(
        filter_by={'primary_attribute': PrimaryAttribute.CONTENT_HASH}
    )
    print(f"\nNumber of content-hash based protocols: {len(content_hash_protocols)}")
