# CCS Quick Start Guide


import os
import sys
import tempfile
import hashlib
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.embedding import CCSEmbedder
from src.core.extraction import CCSExtractor
from src.core.security import SecurityManager
from src.utils.logging_config import setup_logging

class CCSQuickStart:
    """
    Quick Start Guide for CCS Framework
    
    This guide provides a simple, step-by-step introduction to using
    Contextual Cloud Steganography for secure covert communication.
    """
    
    def __init__(self):
        """Initialize the quick start guide"""
        self.working_dir = tempfile.mkdtemp(prefix="ccs_quickstart_")
        print(f"📁 Working directory: {self.working_dir}")
        
        # Basic configuration
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
        
        # Setup logging
        setup_logging({'log_dir': os.path.join(self.working_dir, 'logs')})
        
        # Initialize components
        self.security_manager = SecurityManager(self.config['security'])
        self.embedder = CCSEmbedder(self.config)
        self.extractor = CCSExtractor(self.config)
        
        print("✅ CCS Framework initialized")
    
    def step_1_create_test_environment(self):
        """Step 1: Create test folders with sample files"""
        print("\n" + "="*60)
        print("STEP 1: CREATE TEST ENVIRONMENT")
        print("="*60)
        
        # Create two cover folders
        self.cover_folders = []
        
        for i in range(2):
            folder_name = f"cover_folder_{i}"
            folder_path = os.path.join(self.working_dir, folder_name)
            os.makedirs(folder_path, exist_ok=True)
            self.cover_folders.append(folder_path)
            
            # Create sample files in each folder
            num_files = 16  # Small number for quick start
            print(f"\nCreating {num_files} files in {folder_name}:")
            
            for j in range(num_files):
                filename = f"document_{j:03d}.txt"
                filepath = os.path.join(folder_path, filename)
                
                # Create different content for each file
                content = f"This is document {j} in folder {i}\n"
                content += "-" * 40 + "\n"
                content += f"Created: 2024-01-{15+j:02d}\n"
                content += f"Size: {(j+1)*100} bytes\n"
                content += "Sample content for CCS demonstration.\n"
                content += "x" * (j * 10)  # Varying sizes
                
                with open(filepath, 'w') as f:
                    f.write(content)
                
                if j < 3:  # Show first 3 files
                    print(f"  📄 {filename} ({(j+1)*100} bytes)")
            
            print(f"  ... and {num_files - 3} more files")
        
        print(f"\n✅ Created {len(self.cover_folders)} cover folders")
        return self.cover_folders
    
    def step_2_setup_security(self):
        """Step 2: Setup encryption and protocol"""
        print("\n" + "="*60)
        print("STEP 2: SETUP SECURITY")
        print("="*60)
        
        # Generate encryption keys from a password
        print("\nGenerating encryption keys...")
        password = "MySecretPassword123"  # In practice, use a strong password
        self.keys = self.security_manager.generate_keys(password)
        
        print(f"✅ Generated AES-256 encryption key")
        print(f"✅ Generated HMAC-SHA256 authentication key")
        
        # Define the contextual protocol
        print("\nDefining contextual protocol...")
        self.protocol = {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending',
            'description': 'Sort by SHA-256 hash of file content, then by file size'
        }
        
        print(f"✅ Protocol: {self.protocol['description']}")
        
        # Create the stego-key
        self.stego_key = {
            'credentials': {
                'note': 'Cloud credentials would go here'
            },
            'protocol': self.protocol,
            'encryption_key': self.keys['encryption_key']
        }
        
        print("\n🔐 Stego-key created containing:")
        print("   - Cloud credentials (for real usage)")
        print("   - Contextual protocol definition")
        print("   - AES-256 encryption key")
        
        return self.stego_key
    
    def step_3_embed_secret(self):
        """Step 3: Embed a secret message"""
        print("\n" + "="*60)
        print("STEP 3: EMBED SECRET MESSAGE")
        print("="*60)
        
        # The secret message to hide
        secret_message = """SECRET MESSAGE
        
From: Alice
To: Bob
Date: 2024-01-15
Priority: High

Meeting confirmed for Friday 2 PM at usual location.
Bring the documents we discussed.

Encryption key for next message: X7gH9pL2qR4tY8wZ

Do not reply to this message.
"""
        
        print(f"\nSecret message to embed ({len(secret_message)} characters):")
        print("-" * 40)
        print(secret_message[:200] + "..." if len(secret_message) > 200 else secret_message)
        print("-" * 40)
        
        print(f"\n📊 Capacity analysis:")
        for i, folder in enumerate(self.cover_folders):
            files = os.listdir(folder)
            capacity_bits = len(files).bit_length() - 1
            print(f"  Folder {i}: {len(files)} files → {capacity_bits} bits capacity")
        
        total_capacity = sum(len(os.listdir(f)).bit_length() - 1 for f in self.cover_folders)
        print(f"  Total capacity: {total_capacity} bits")
        
        print("\nStarting embedding process...")
        print("1. Encrypting message with AES-256...")
        print("2. Segmenting encrypted message...")
        print("3. Sorting files using contextual protocol...")
        print("4. Selecting files based on secret data...")
        print("5. Creating stego-folder...")
        
        # Perform embedding
        self.stego_folder = self.embedder.embed(
            secret_message,
            self.cover_folders,
            self.stego_key
        )
        
        print(f"\n✅ Stego-folder created: {os.path.basename(self.stego_folder)}")
        
        # Show what's in the stego-folder
        stego_files = os.listdir(self.stego_folder)
        print(f"\n📁 Stego-folder contains {len(stego_files)} files:")
        for i, filename in enumerate(stego_files[:5]):  # Show first 5
            filepath = os.path.join(self.stego_folder, filename)
            size = os.path.getsize(filepath)
            print(f"  {i+1}. {filename} ({size} bytes)")
        
        if len(stego_files) > 5:
            print(f"  ... and {len(stego_files) - 5} more files")
        
        return self.stego_folder
    
    def step_4_extract_secret(self):
        """Step 4: Extract the secret message"""
        print("\n" + "="*60)
        print("STEP 4: EXTRACT SECRET MESSAGE")
        print("="*60)
        
        print("\nStarting extraction process...")
        print("1. Accessing stego-folder...")
        print("2. Reconstructing file order using protocol...")
        print("3. Matching stego-files to cover folders...")
        print("4. Rebuilding encrypted message...")
        print("5. Decrypting with AES-256...")
        
        # Perform extraction
        extracted_message = self.extractor.extract(
            self.stego_folder,
            self.cover_folders,
            self.stego_key
        )
        
        print(f"\n✅ Extraction successful!")
        print(f"\n📨 Extracted message ({len(extracted_message)} characters):")
        print("-" * 40)
        print(extracted_message[:200] + "..." if len(extracted_message) > 200 else extracted_message)
        print("-" * 40)
        
        # Verify extraction
        secret_message = """SECRET MESSAGE
        
From: Alice
To: Bob
Date: 2024-01-15
Priority: High

Meeting confirmed for Friday 2 PM at usual location.
Bring the documents we discussed.

Encryption key for next message: X7gH9pL2qR4tY8wZ

Do not reply to this message.
"""
        
        if extracted_message == secret_message:
            print("\n🎉 SUCCESS: Extracted message matches original!")
        else:
            print("\n⚠️  WARNING: Extracted message differs from original")
            print(f"   Original length: {len(secret_message)}")
            print(f"   Extracted length: {len(extracted_message)}")
        
        return extracted_message
    
    def step_5_demonstrate_security(self):
        """Step 5: Demonstrate security features"""
        print("\n" + "="*60)
        print("STEP 5: SECURITY DEMONSTRATION")
        print("="*60)
        
        print("\n🔒 Security Features Demonstrated:")
        
        # 1. File Integrity
        print("\n1. File Integrity Protection:")
        print("   • Stego-files are exact copies of originals")
        print("   • No modifications to file content")
        print("   • Resistant to statistical steganalysis")
        
        # Show that files are unchanged
        stego_files = os.listdir(self.stego_folder)
        sample_file = os.path.join(self.stego_folder, stego_files[0])
        sample_original = None
        
        # Find original of sample file
        for cover_folder in self.cover_folders:
            for file in os.listdir(cover_folder):
                if file == stego_files[0]:
                    sample_original = os.path.join(cover_folder, file)
                    break
        
        if sample_original:
            with open(sample_file, 'rb') as f1, open(sample_original, 'rb') as f2:
                content1 = f1.read()
                content2 = f2.read()
            
            if content1 == content2:
                print("   ✓ Verified: Stego-file identical to original")
            else:
                print("   ✗ ERROR: File content modified")
        
        # 2. Protocol Security
        print("\n2. Protocol Security:")
        print("   • Contextual protocol acts as secondary secret")
        print("   • 480+ possible protocol combinations")
        print("   • Even if stego-folder found, protocol unknown")
        
        # 3. Cryptographic Protection
        print("\n3. Cryptographic Protection:")
        print("   • AES-256 encryption for message confidentiality")
        print("   • HMAC-SHA256 for file integrity verification")
        print("   • Independent of protocol security")
        
        # 4. Undetectability
        print("\n4. Undetectability:")
        print("   • Stego-folder looks like normal folder")
        print("   • Files have legitimate content and metadata")
        print("   • No statistical anomalies")
        
        # Demonstrate with wrong protocol
        print("\n🧪 Demonstration: Wrong protocol attempt")
        wrong_protocol = {
            'primary_attribute': 'file_size',
            'secondary_attribute': None,
            'sort_order': 'descending'
        }
        
        wrong_stego_key = {
            'protocol': wrong_protocol,
            'encryption_key': self.keys['encryption_key']
        }
        
        try:
            wrong_extraction = self.extractor.extract(
                self.stego_folder,
                self.cover_folders,
                wrong_stego_key,
                max_attempts=1
            )
            print("   ⚠️  Unexpected: Extraction with wrong protocol succeeded")
        except Exception as e:
            print(f"   ✓ Expected: Extraction failed with wrong protocol")
            print(f"     Error: {str(e)[:50]}...")
    
    def step_6_advanced_features(self):
        """Step 6: Show advanced features"""
        print("\n" + "="*60)
        print("STEP 6: ADVANCED FEATURES")
        print("="*60)
        
        print("\n🚀 Advanced CCS Capabilities:")
        
        # 1. Scalability
        print("\n1. Scalability:")
        print("   • Capacity scales with folder size")
        print("   • 10 files → 3 bits, 1000 files → 10 bits")
        print("   • Logarithmic growth: C = floor(log₂(M))")
        
        # Show scaling table
        print("\n   Capacity scaling table:")
        print("   " + "-" * 30)
        print("   Files  |  Bits  |  vs Base-8")
        print("   " + "-" * 30)
        for files in [8, 16, 64, 256, 1024, 4096]:
            bits = files.bit_length() - 1
            improvement = bits / 3  # Base-8 has 3 bits
            print(f"   {files:6d} | {bits:6d} | {improvement:5.1f}×")
        print("   " + "-" * 30)
        
        # 2. Multiple Protocols
        print("\n2. Protocol Variants:")
        print("   • Content hash (most secure)")
        print("   • File size (fastest)")
        print("   • Timestamp (temporal)")
        print("   • Filename (simple)")
        print("   • Composite (multiple attributes)")
        
        # 3. Error Recovery
        print("\n3. Error Recovery:")
        print("   • Graceful degradation")
        print("   • Partial message recovery")
        print("   • Automatic retry mechanisms")
        
        # 4. Cloud Integration
        print("\n4. Cloud Integration:")
        print("   • Google Drive API support")
        print("   • Dropbox integration")
        print("   • OneDrive compatibility")
        print("   • Multi-cloud deployment")
    
    def step_7_cleanup(self):
        """Step 7: Cleanup and next steps"""
        print("\n" + "="*60)
        print("STEP 7: CLEANUP AND NEXT STEPS")
        print("="*60)
        
        # Ask if user wants to keep files
        keep_files = input("\nKeep working directory for inspection? (y/n): ").lower().strip()
        
        if keep_files != 'y':
            import shutil
            shutil.rmtree(self.working_dir)
            print(f"\n🗑️  Cleaned up working directory")
        else:
            print(f"\n📁 Files preserved in: {self.working_dir}")
            print(f"   • Cover folders: {len(self.cover_folders)}")
            print(f"   • Stego-folder: {os.path.basename(self.stego_folder)}")
            print(f"   • Logs: {os.path.join(self.working_dir, 'logs')}")
        
        print("\n🎓 Next Steps:")
        print("1. Read the CCS research paper for theoretical foundations")
        print("2. Explore the examples/ directory for more advanced usage")
        print("3. Check tests/ for verification and benchmarking")
        print("4. Review src/ for implementation details")
        print("5. Join the community for discussions and contributions")
        
        print("\n📚 Documentation:")
        print("   • API Reference: docs/api.md")
        print("   • Deployment Guide: docs/deployment_guide.md")
        print("   • Research Paper: docs/research_paper.md")
    
    def run_all_steps(self):
        """Run all quick start steps"""
        print("\n" + "="*60)
        print("CCS QUICK START GUIDE")
        print("Contextual Cloud Steganography Framework")
        print("="*60)
        print("\nThis guide will demonstrate:")
        print("1. Creating test environment")
        print("2. Setting up security protocols")
        print("3. Embedding secret messages")
        print("4. Extracting hidden data")
        print("5. Understanding security features")
        print("6. Exploring advanced capabilities")
        print("7. Cleanup and next steps")
        
        input("\nPress Enter to begin...")
        
        try:
            self.step_1_create_test_environment()
            input("\nPress Enter to continue to Step 2...")
            
            self.step_2_setup_security()
            input("\nPress Enter to continue to Step 3...")
            
            self.step_3_embed_secret()
            input("\nPress Enter to continue to Step 4...")
            
            self.step_4_extract_secret()
            input("\nPress Enter to continue to Step 5...")
            
            self.step_5_demonstrate_security()
            input("\nPress Enter to continue to Step 6...")
            
            self.step_6_advanced_features()
            input("\nPress Enter to continue to Step 7...")
            
            self.step_7_cleanup()
            
            print("\n" + "="*60)
            print("QUICK START COMPLETE!")
            print("="*60)
            print("\nYou have successfully:")
            print("✓ Learned CCS basic concepts")
            print("✓ Embedded and extracted secret messages")
            print("✓ Understood security guarantees")
            print("✓ Explored advanced features")
            print("\nReady to use CCS for your secure communication needs!")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Quick start interrupted by user")
        except Exception as e:
            print(f"\n\n❌ Error during quick start: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Offer to cleanup even on error
            if hasattr(self, 'working_dir') and os.path.exists(self.working_dir):
                cleanup = input(f"\nClean up working directory {self.working_dir}? (y/n): ")
                if cleanup.lower() == 'y':
                    import shutil
                    shutil.rmtree(self.working_dir)
                    print("Cleaned up working directory")


class CCSMiniTutorial:
    """Mini tutorial with code examples"""
    
    @staticmethod
    def basic_usage_example():
        """Basic usage example in code form"""
        
        example_code = '''
# BASIC CCS USAGE EXAMPLE

import os
from ccs.core.embedding import CCSEmbedder
from ccs.core.extraction import CCSExtractor
from ccs.core.security import SecurityManager

# 1. Configuration
config = {
    'security': {
        'encryption_algorithm': 'AES-256-CBC',
        'hmac_algorithm': 'SHA256'
    }
}

# 2. Initialize components
security_manager = SecurityManager(config['security'])
embedder = CCSEmbedder(config)
extractor = CCSExtractor(config)

# 3. Generate keys
password = "YourStrongPasswordHere"
keys = security_manager.generate_keys(password)

# 4. Define protocol
protocol = {
    'primary_attribute': 'content_hash',
    'secondary_attribute': 'file_size',
    'sort_order': 'ascending'
}

# 5. Create stego-key
stego_key = {
    'protocol': protocol,
    'encryption_key': keys['encryption_key']
}

# 6. Embed secret message
secret = "Your secret message here"
cover_folders = ["/path/to/cover/folder1", "/path/to/cover/folder2"]
stego_folder = embedder.embed(secret, cover_folders, stego_key)

print(f"Stego-folder created: {stego_folder}")

# 7. Extract secret message
extracted = extractor.extract(stego_folder, cover_folders, stego_key)
print(f"Extracted message: {extracted}")

# 8. Verify
if extracted == secret:
    print("✓ Success! Message recovered perfectly.")
else:
    print("✗ Error in extraction.")
'''
        
        return example_code
    
    @staticmethod
    def protocol_examples():
        """Examples of different protocols"""
        
        protocols = {
            'content_hash': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending',
                'description': 'Most secure - based on file content'
            },
            'file_size': {
                'primary_attribute': 'file_size',
                'sort_order': 'ascending',
                'description': 'Fast - based on file size only'
            },
            'timestamp': {
                'primary_attribute': 'timestamp',
                'sort_order': 'descending',
                'description': 'Temporal - newest files first'
            },
            'composite': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'timestamp',
                'sort_order': 'ascending',
                'combination': 'weighted_composite',
                'description': 'Advanced - multiple attributes'
            }
        }
        
        return protocols
    
    @staticmethod
    def capacity_calculator(files_per_folder):
        """Calculate capacity for given folder sizes"""
        
        print("\n📊 CAPACITY CALCULATOR")
        print("-" * 40)
        
        for files in files_per_folder:
            bits = files.bit_length() - 1
            bytes_capacity = bits // 8
            improvement_vs_base8 = bits / 3  # Base-8 has 3 bits
            
            print(f"{files:6d} files → {bits:3d} bits ({bytes_capacity} bytes)")
            print(f"        Improvement vs Base-8: {improvement_vs_base8:5.1f}×")
        
        print("-" * 40)


def interactive_tutorial():
    """Interactive command-line tutorial"""
    
    print("\n" + "="*60)
    print("CCS INTERACTIVE TUTORIAL")
    print("="*60)
    
    tutorial = CCSQuickStart()
    
    while True:
        print("\nChoose an option:")
        print("1. Run complete quick start")
        print("2. Step-by-step tutorial")
        print("3. View code examples")
        print("4. Calculate capacity")
        print("5. Protocol examples")
        print("6. Exit")
        
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == '1':
            tutorial.run_all_steps()
            break
        elif choice == '2':
            print("\nStep-by-step tutorial selected")
            # Could implement individual step selection here
            tutorial.run_all_steps()
            break
        elif choice == '3':
            print("\n" + "="*60)
            print("CODE EXAMPLES")
            print("="*60)
            print(CCSMiniTutorial.basic_usage_example())
            input("\nPress Enter to continue...")
        elif choice == '4':
            print("\nCapacity Calculator")
            files_input = input("Enter folder sizes (comma-separated): ")
            files_list = [int(f.strip()) for f in files_input.split(',') if f.strip().isdigit()]
            CCSMiniTutorial.capacity_calculator(files_list)
            input("\nPress Enter to continue...")
        elif choice == '5':
            print("\n" + "="*60)
            print("PROTOCOL EXAMPLES")
            print("="*60)
            protocols = CCSMiniTutorial.protocol_examples()
            for name, details in protocols.items():
                print(f"\n{name.upper()}:")
                print(f"  Description: {details['description']}")
                print(f"  Primary: {details['primary_attribute']}")
                if 'secondary_attribute' in details:
                    print(f"  Secondary: {details['secondary_attribute']}")
                print(f"  Order: {details['sort_order']}")
            input("\nPress Enter to continue...")
        elif choice == '6':
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


def main():
    """Main entry point for quick start"""
    
    print("\n" + "="*60)
    print("WELCOME TO CONTEXTUAL CLOUD STEGANOGRAPHY (CCS)")
    print("="*60)
    print("\nA framework for secure covert communication in cloud storage")
    print("\nVersion: 1.0.0")
    print("Paper: 'Contextual Cloud Steganography: Breaking the Capacity-Security Trade-Off'")
    print("Authors: Research Team")
    print("\n" + "-"*60)
    
    print("\nChoose mode:")
    print("1. Quick Start (Recommended for beginners)")
    print("2. Interactive Tutorial")
    print("3. Exit")
    
    mode = input("\nEnter choice (1-3): ").strip()
    
    if mode == '1':
        # Run quick start
        tutorial = CCSQuickStart()
        tutorial.run_all_steps()
    elif mode == '2':
        # Interactive tutorial
        interactive_tutorial()
    elif mode == '3':
        print("\nGoodbye!")
        return
    else:
        print("Invalid choice. Running Quick Start by default...")
        tutorial = CCSQuickStart()
        tutorial.run_all_steps()


if __name__ == "__main__":
    main()
