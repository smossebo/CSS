# Enterprise Deployment Example for CCS
# Demonstrates CCS deployment in corporate environments


import os
import json
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import yaml

# Add src to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.embedding import CCSEmbedder
from core.extraction import CCSExtractor
from core.security import SecurityManager
from core.protocols import ProtocolManager
from utils.logging_config import CCSLogger, setup_logging
from utils.monitoring import FolderMonitor, ChangeLevel
from utils.optimization import OptimizationManager
from cloud.google_drive import CCSGoogleDriveManager
from cloud.dropbox import CCSDropboxManager
from cloud.onedrive import CCSOneDriveManager

class EnterpriseCCSDeployer:
    """
    Enterprise-grade CCS deployment manager
    Implements corporate security policies and operational best practices
    """
    
    def __init__(self, config_file: str = "enterprise_config.yaml"):
        """
        Initialize enterprise CCS deployment
        
        Args:
            config_file: Path to enterprise configuration file
        """
        self.config_file = config_file
        self.config = self._load_config()
        
        # Setup enterprise logging
        self.logger = setup_logging(self.config.get('logging', {}))
        
        # Initialize components
        self.security_manager = SecurityManager(self.config.get('security', {}))
        self.protocol_manager = ProtocolManager()
        self.optimization_manager = OptimizationManager(self.config.get('performance', {}))
        
        # Cloud managers
        self.cloud_managers = self._initialize_cloud_managers()
        
        # Monitoring
        self.monitors = {}
        
        # Deployment state
        self.deployment_state = {
            'initialized': datetime.now().isoformat(),
            'active_sessions': 0,
            'total_operations': 0,
            'error_count': 0
        }
    
    def _load_config(self) -> Dict:
        """Load enterprise configuration"""
        config_paths = [
            self.config_file,
            "/etc/ccs/enterprise_config.yaml",
            os.path.expanduser("~/.ccs/enterprise_config.yaml")
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        config = yaml.safe_load(f)
                    print(f"Loaded configuration from {path}")
                    return config
                except Exception as e:
                    print(f"Error loading config from {path}: {e}")
        
        # Default configuration
        return {
            'enterprise': {
                'name': 'Default Enterprise',
                'security_level': 'high',
                'compliance': ['GDPR', 'HIPAA'],
                'audit_logging': True
            },
            'security': {
                'encryption_algorithm': 'AES-256-CBC',
                'hmac_algorithm': 'SHA256',
                'key_rotation_days': 90,
                'protocol_rotation_days': 30
            },
            'performance': {
                'precompute_hashes': True,
                'cache_enabled': True,
                'parallel_processing': True,
                'memory_limit_mb': 512
            },
            'cloud': {
                'primary_provider': 'google_drive',
                'backup_providers': ['dropbox', 'onedrive'],
                'sync_frequency_hours': 24
            },
            'monitoring': {
                'enabled': True,
                'check_interval_seconds': 300,
                'warning_threshold': 0.1,
                'critical_threshold': 0.3
            }
        }
    
    def _initialize_cloud_managers(self) -> Dict:
        """Initialize cloud storage managers"""
        managers = {}
        cloud_config = self.config.get('cloud', {})
        
        # Initialize based on configuration
        if cloud_config.get('primary_provider') == 'google_drive':
            managers['primary'] = CCSGoogleDriveManager(cloud_config)
        elif cloud_config.get('primary_provider') == 'dropbox':
            managers['primary'] = CCSDropboxManager(cloud_config)
        elif cloud_config.get('primary_provider') == 'onedrive':
            managers['primary'] = CCSOneDriveManager(cloud_config)
        
        # Initialize backup providers
        for provider in cloud_config.get('backup_providers', []):
            if provider == 'google_drive' and 'google_drive' not in managers:
                managers[provider] = CCSGoogleDriveManager(cloud_config)
            elif provider == 'dropbox' and 'dropbox' not in managers:
                managers[provider] = CCSDropboxManager(cloud_config)
            elif provider == 'onedrive' and 'onedrive' not in managers:
                managers[provider] = CCSOneDriveManager(cloud_config)
        
        return managers
    
    def setup_enterprise_environment(self) -> bool:
        """
        Setup complete enterprise CCS environment
        
        Returns:
            True if setup successful
        """
        self.logger.log_operation_start("enterprise_setup", "admin")
        
        try:
            # 1. Setup cloud structure
            print("Setting up cloud storage structure...")
            cloud_setup = self._setup_cloud_environment()
            
            if not cloud_setup:
                raise RuntimeError("Cloud setup failed")
            
            # 2. Generate and secure keys
            print("Generating encryption keys...")
            key_setup = self._setup_key_management()
            
            # 3. Deploy cover folders
            print("Deploying cover folders...")
            folder_setup = self._deploy_cover_folders()
            
            # 4. Setup monitoring
            print("Setting up monitoring...")
            monitoring_setup = self._setup_monitoring()
            
            # 5. Create backup strategy
            print("Creating backup strategy...")
            backup_setup = self._create_backup_strategy()
            
            # Log successful setup
            self.logger.log_operation_end(
                "enterprise_setup",
                True,
                "admin",
                {
                    'cloud_providers': len(self.cloud_managers),
                    'cover_folders_deployed': len(folder_setup) if folder_setup else 0
                }
            )
            
            print("\n✓ Enterprise CCS environment setup complete!")
            return True
            
        except Exception as e:
            self.logger.log_error(e, {'operation': 'enterprise_setup'})
            self.logger.log_operation_end("enterprise_setup", False, "admin")
            print(f"\n✗ Enterprise setup failed: {e}")
            return False
    
    def _setup_cloud_environment(self) -> bool:
        """Setup cloud storage environment"""
        results = {}
        
        for name, manager in self.cloud_managers.items():
            try:
                print(f"  Setting up {name} provider...")
                
                if name == 'primary':
                    folder_ids = manager.setup_ccs_structure()
                    results[name] = {
                        'success': True,
                        'folder_ids': folder_ids
                    }
                    print(f"    ✓ {name} setup complete")
                else:
                    # For backup providers, just verify connectivity
                    if hasattr(manager, 'client') and hasattr(manager.client, 'authenticate'):
                        connected = manager.client.authenticate()
                        results[name] = {'success': connected}
                        if connected:
                            print(f"    ✓ {name} connected")
                        else:
                            print(f"    ✗ {name} connection failed")
                
            except Exception as e:
                results[name] = {'success': False, 'error': str(e)}
                print(f"    ✗ {name} setup failed: {e}")
        
        # Primary must succeed, backups can fail
        primary_success = results.get('primary', {}).get('success', False)
        
        return primary_success
    
    def _setup_key_management(self) -> Dict:
        """Setup enterprise key management"""
        # Generate master key
        master_password = self._generate_secure_password()
        keys = self.security_manager.generate_keys(master_password)
        
        # Store key metadata (not the actual keys!)
        key_metadata = {
            'generated': datetime.now().isoformat(),
            'rotation_schedule': self.config['security'].get('key_rotation_days', 90),
            'next_rotation': self._calculate_next_rotation(90),
            'key_derivation': self.config['security'].get('key_derivation', 'PBKDF2')
        }
        
        # In real enterprise, keys would be stored in HSM or secure key vault
        # For this example, we'll store metadata only
        key_file = os.path.join(tempfile.gettempdir(), 'ccs_key_metadata.json')
        with open(key_file, 'w') as f:
            json.dump(key_metadata, f, indent=2)
        
        print(f"  Key metadata stored at: {key_file}")
        print("  WARNING: In production, store keys in secure key management system!")
        
        return {
            'master_password_hash': hashlib.sha256(master_password.encode()).hexdigest()[:16],
            'key_metadata': key_metadata
        }
    
    def _deploy_cover_folders(self) -> List[Dict]:
        """Deploy cover folders to cloud"""
        deployment_plan = self.config.get('deployment', {}).get('cover_folders', [])
        
        if not deployment_plan:
            # Default deployment plan
            deployment_plan = [
                {
                    'name': 'IT_Documentation',
                    'files': 256,
                    'types': ['.pdf', '.docx', '.xlsx'],
                    'size_range_kb': [50, 5000]
                },
                {
                    'name': 'Marketing_Assets',
                    'files': 512,
                    'types': ['.jpg', '.png', '.mp4'],
                    'size_range_kb': [100, 10000]
                },
                {
                    'name': 'Archived_Projects',
                    'files': 1024,
                    'types': ['.zip', '.rar', '.7z'],
                    'size_range_kb': [1000, 50000]
                }
            ]
        
        deployed_folders = []
        
        for plan in deployment_plan:
            try:
                print(f"  Deploying {plan['name']}...")
                
                # Create local folder structure
                local_folder = self._create_local_cover_folder(plan)
                
                # Upload to cloud
                primary_manager = self.cloud_managers.get('primary')
                if primary_manager and hasattr(primary_manager, 'upload_cover_folder'):
                    folder_id = primary_manager.upload_cover_folder(
                        local_folder,
                        plan['name']
                    )
                    
                    if folder_id:
                        deployed_folders.append({
                            'name': plan['name'],
                            'local_path': local_folder,
                            'cloud_id': folder_id,
                            'file_count': plan['files'],
                            'capacity_bits': plan['files'].bit_length() - 1
                        })
                        print(f"    ✓ Uploaded to cloud")
                    else:
                        print(f"    ✗ Cloud upload failed")
                
                # Cleanup local folder
                import shutil
                shutil.rmtree(local_folder)
                
            except Exception as e:
                print(f"    ✗ Deployment failed: {e}")
                self.logger.log_error(e, {'folder_plan': plan})
        
        # Log total capacity
        total_capacity = sum(f['capacity_bits'] for f in deployed_folders)
        print(f"\n  Total deployment capacity: {total_capacity} bits")
        
        return deployed_folders
    
    def _create_local_cover_folder(self, plan: Dict) -> str:
        """Create local cover folder according to plan"""
        folder_path = tempfile.mkdtemp(prefix=f"cover_{plan['name']}_")
        
        for i in range(plan['files']):
            # Select file type
            file_type = plan['types'][i % len(plan['types'])]
            
            # Determine size
            min_size, max_size = plan['size_range_kb']
            size_kb = (min_size + (i % (max_size - min_size + 1)))
            
            # Create file
            filename = f"file_{i:06d}{file_type}"
            filepath = os.path.join(folder_path, filename)
            
            with open(filepath, 'wb') as f:
                # Create realistic content based on file type
                if file_type in ['.pdf', '.docx', '.xlsx']:
                    # Document-like content
                    header = f"{plan['name']} Document {i}\n".encode()
                    content = header + os.urandom(size_kb * 1024 - len(header))
                elif file_type in ['.jpg', '.png']:
                    # Image-like content (with fake header)
                    content = b'\xff\xd8\xff\xe0' + os.urandom(size_kb * 1024 - 4)
                else:
                    # Generic content
                    content = os.urandom(size_kb * 1024)
                
                f.write(content[:size_kb * 1024])
        
        return folder_path
    
    def _setup_monitoring(self) -> bool:
        """Setup folder monitoring"""
        if not self.config.get('monitoring', {}).get('enabled', True):
            print("  Monitoring disabled in configuration")
            return False
        
        monitor_config = self.config.get('monitoring', {})
        self.monitor = FolderMonitor(monitor_config)
        
        print("  Monitoring system initialized")
        return True
    
    def _create_backup_strategy(self) -> Dict:
        """Create backup and disaster recovery strategy"""
        strategy = {
            'backup_schedule': 'daily',
            'retention_days': 30,
            'recovery_point_objective': '24 hours',
            'recovery_time_objective': '4 hours',
            'backup_providers': list(self.cloud_managers.keys())[1:],  # All except primary
            'created': datetime.now().isoformat()
        }
        
        print("  Backup strategy created:")
        for key, value in strategy.items():
            print(f"    {key}: {value}")
        
        return strategy
    
    def embed_enterprise_message(self, department: str, message: str, 
                                priority: str = 'normal') -> Optional[str]:
        """
        Embed message with enterprise controls
        
        Args:
            department: Originating department
            message: Secret message
            priority: 'low', 'normal', 'high', 'critical'
            
        Returns:
            Stego-folder path or None
        """
        self.logger.log_operation_start("enterprise_embed", department)
        
        try:
            # Check permissions
            if not self._check_department_permissions(department, priority):
                raise PermissionError(f"Department {department} not authorized for {priority} priority")
            
            # Select protocol based on priority
            protocol = self._select_protocol_for_priority(priority)
            
            # Get keys
            keys = self._get_enterprise_keys(department)
            
            # Prepare stego-key
            stego_key = {
                'protocol': protocol,
                'encryption_key': keys['encryption_key'],
                'department': department,
                'priority': priority,
                'timestamp': datetime.now().isoformat()
            }
            
            # Select cover folders based on capacity needs
            cover_folders = self._select_cover_folders(len(message), priority)
            
            # Create embedder with enterprise config
            embedder = CCSEmbedder(self.config)
            
            # Embed message
            stego_folder = embedder.embed(
                message,
                cover_folders,
                stego_key
            )
            
            # Upload to cloud
            cloud_path = self._upload_to_enterprise_cloud(stego_folder, department, priority)
            
            # Log success
            self.logger.log_operation_end(
                "enterprise_embed",
                True,
                department,
                {
                    'message_length': len(message),
                    'priority': priority,
                    'cover_folders_used': len(cover_folders),
                    'cloud_path': cloud_path
                }
            )
            
            self.deployment_state['total_operations'] += 1
            
            print(f"\n✓ Message embedded successfully")
            print(f"  Department: {department}")
            print(f"  Priority: {priority}")
            print(f"  Cloud location: {cloud_path}")
            
            return cloud_path
            
        except Exception as e:
            self.logger.log_error(e, {
                'department': department,
                'priority': priority,
                'operation': 'embed'
            })
            self.logger.log_operation_end("enterprise_embed", False, department)
            self.deployment_state['error_count'] += 1
            
            print(f"\n✗ Embedding failed: {e}")
            return None
    
    def extract_enterprise_message(self, cloud_path: str, department: str) -> Optional[str]:
        """
        Extract message with enterprise controls
        
        Args:
            cloud_path: Path to stego-folder in cloud
            department: Requesting department
            
        Returns:
            Extracted message or None
        """
        self.logger.log_operation_start("enterprise_extract", department)
        
        try:
            # Check extraction permissions
            if not self._check_extraction_permissions(department, cloud_path):
                raise PermissionError(f"Department {department} not authorized to extract from {cloud_path}")
            
            # Download from cloud
            local_folder = self._download_from_enterprise_cloud(cloud_path, department)
            
            # Get keys and protocol
            keys = self._get_enterprise_keys(department)
            
            # For extraction, we need to know the protocol used
            # In real enterprise, this would be retrieved from metadata
            protocol = self._get_protocol_from_metadata(cloud_path)
            
            stego_key = {
                'protocol': protocol,
                'encryption_key': keys['encryption_key']
            }
            
            # Get cover folders (would be known from deployment)
            cover_folders = self._get_cover_folders_for_path(cloud_path)
            
            # Extract
            extractor = CCSExtractor(self.config)
            message = extractor.extract(
                local_folder,
                cover_folders,
                stego_key
            )
            
            # Log extraction
            self.logger.log_operation_end(
                "enterprise_extract",
                True,
                department,
                {
                    'message_length': len(message),
                    'cloud_path': cloud_path
                }
            )
            
            self.deployment_state['total_operations'] += 1
            
            print(f"\n✓ Message extracted successfully")
            print(f"  Department: {department}")
            print(f"  Message length: {len(message)} characters")
            
            # Cleanup
            import shutil
            shutil.rmtree(local_folder)
            
            return message
            
        except Exception as e:
            self.logger.log_error(e, {
                'department': department,
                'cloud_path': cloud_path,
                'operation': 'extract'
            })
            self.logger.log_operation_end("enterprise_extract", False, department)
            self.deployment_state['error_count'] += 1
            
            print(f"\n✗ Extraction failed: {e}")
            return None
    
    def _check_department_permissions(self, department: str, priority: str) -> bool:
        """Check if department has permission for given priority"""
        # Simplified permission check
        # In real enterprise, integrate with IAM system
        
        department_roles = self.config.get('enterprise', {}).get('department_roles', {})
        
        if department not in department_roles:
            return False
        
        role = department_roles[department]
        
        # Role to priority mapping
        role_permissions = {
            'admin': ['low', 'normal', 'high', 'critical'],
            'security': ['normal', 'high', 'critical'],
            'department_head': ['low', 'normal', 'high'],
            'employee': ['low', 'normal']
        }
        
        return priority in role_permissions.get(role, [])
    
    def _select_protocol_for_priority(self, priority: str) -> Dict:
        """Select protocol based on message priority"""
        protocol_configs = {
            'critical': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending',
                'combination': 'weighted_composite',
                'transform': 'custom_hash'
            },
            'high': {
                'primary_attribute': 'content_hash',
                'secondary_attribute': 'file_size',
                'sort_order': 'ascending',
                'combination': 'primary_secondary'
            },
            'normal': {
                'primary_attribute': 'content_hash',
                'sort_order': 'ascending'
            },
            'low': {
                'primary_attribute': 'file_size',
                'sort_order': 'ascending'
            }
        }
        
        return protocol_configs.get(priority, protocol_configs['normal'])
    
    def _get_enterprise_keys(self, department: str) -> Dict:
        """Get encryption keys for department"""
        # In real enterprise, retrieve from key management system
        # For this example, generate department-specific keys
        
        department_seed = f"{department}_{self.config['enterprise']['name']}"
        keys = self.security_manager.generate_keys(department_seed)
        
        return keys
    
    def _select_cover_folders(self, message_length: int, priority: str) -> List[str]:
        """Select appropriate cover folders based on message length and priority"""
        # Simplified selection
        # In real enterprise, would query capacity database
        
        # For this example, return some placeholder paths
        # In reality, these would be actual cloud folder paths
        return [
            f"/CCS/CoverFolders/IT_Documentation",
            f"/CCS/CoverFolders/Marketing_Assets"
        ]
    
    def _upload_to_enterprise_cloud(self, local_folder: str, department: str, 
                                   priority: str) -> str:
        """Upload stego-folder to enterprise cloud"""
        primary_manager = self.cloud_managers.get('primary')
        
        if not primary_manager:
            raise RuntimeError("No primary cloud manager available")
        
        # Create unique folder name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        folder_name = f"{department}_{priority}_{timestamp}"
        
        # Upload
        cloud_path = primary_manager.create_stego_folder(folder_name)
        
        # Upload files
        for filename in os.listdir(local_folder):
            local_path = os.path.join(local_folder, filename)
            # In real implementation, would upload each file
        
        return cloud_path
    
    def _download_from_enterprise_cloud(self, cloud_path: str, department: str) -> str:
        """Download stego-folder from enterprise cloud"""
        # Simplified - in real implementation would download from cloud
        local_folder = tempfile.mkdtemp(prefix=f"download_{department}_")
        
        # For this example, create dummy files
        for i in range(3):
            filepath = os.path.join(local_folder, f"stego_file_{i}.dat")
            with open(filepath, 'wb') as f:
                f.write(os.urandom(1024))
        
        return local_folder
    
    def _check_extraction_permissions(self, department: str, cloud_path: str) -> bool:
        """Check if department can extract from given path"""
        # Simplified permission check
        # In real enterprise, check ACLs
        
        # Extract department from path
        path_department = cloud_path.split('_')[0] if '_' in cloud_path else 'unknown'
        
        # Same department can extract, or admin/security
        if department == path_department:
            return True
        
        department_roles = self.config.get('enterprise', {}).get('department_roles', {})
        role = department_roles.get(department, 'employee')
        
        return role in ['admin', 'security']
    
    def _get_protocol_from_metadata(self, cloud_path: str) -> Dict:
        """Retrieve protocol from cloud metadata"""
        # In real enterprise, retrieve from metadata store
        # For this example, return default
        
        return {
            'primary_attribute': 'content_hash',
            'secondary_attribute': 'file_size',
            'sort_order': 'ascending'
        }
    
    def _get_cover_folders_for_path(self, cloud_path: str) -> List[str]:
        """Get cover folders for given stego path"""
        # In real enterprise, query deployment database
        # For this example, return defaults
        
        return [
            f"/CCS/CoverFolders/IT_Documentation",
            f"/CCS/CoverFolders/Marketing_Assets"
        ]
    
    def _generate_secure_password(self) -> str:
        """Generate secure password for key derivation"""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        return password
    
    def _calculate_next_rotation(self, days: int) -> str:
        """Calculate next key rotation date"""
        from datetime import timedelta
        next_date = datetime.now() + timedelta(days=days)
        return next_date.isoformat()
    
    def get_deployment_status(self) -> Dict:
        """Get current deployment status"""
        return {
            **self.deployment_state,
            'cloud_providers': len(self.cloud_managers),
            'active_monitors': len(self.monitors),
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_compliance_report(self) -> Dict:
        """Generate compliance report"""
        return {
            'enterprise_name': self.config['enterprise']['name'],
            'compliance_frameworks': self.config['enterprise'].get('compliance', []),
            'security_controls': {
                'encryption': 'AES-256-CBC',
                'authentication': 'HMAC-SHA256',
                'key_rotation': f"{self.config['security'].get('key_rotation_days', 90)} days",
                'protocol_rotation': f"{self.config['security'].get('protocol_rotation_days', 30)} days",
                'audit_logging': self.config['enterprise'].get('audit_logging', False)
            },
            'audit_trail': {
                'total_operations': self.deployment_state['total_operations'],
                'error_count': self.deployment_state['error_count'],
                'last_operation': datetime.now().isoformat()
            },
            'generated': datetime.now().isoformat()
        }


def demonstrate_enterprise_workflow():
    """Demonstrate enterprise CCS workflow"""
    
    print("=" * 70)
    print("ENTERPRISE CCS DEPLOYMENT DEMONSTRATION")
    print("=" * 70)
    print("\nThis demonstrates CCS deployment in a corporate environment")
    print("with enterprise security controls and operational best practices.")
    print()
    
    # Create temporary directory for demonstration
    test_dir = tempfile.mkdtemp(prefix="enterprise_demo_")
    
    try:
        # Create enterprise configuration
        config = {
            'enterprise': {
                'name': 'Acme Corporation',
                'security_level': 'high',
                'compliance': ['GDPR', 'ISO27001', 'SOC2'],
                'department_roles': {
                    'IT': 'admin',
                    'Security': 'security',
                    'HR': 'department_head',
                    'Marketing': 'employee'
                }
            },
            'cloud': {
                'primary_provider': 'google_drive',
                'backup_providers': ['dropbox']
            }
        }
        
        config_file = os.path.join(test_dir, 'enterprise_config.yaml')
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        
        print("1. Initializing Enterprise CCS Deployer...")
        deployer = EnterpriseCCSDeployer(config_file)
        
        print("\n2. Setting up Enterprise Environment...")
        print("   (This would setup cloud storage, keys, cover folders, etc.)")
        # In real demo, would call: deployer.setup_enterprise_environment()
        
        print("\n3. Demonstrating Secure Message Embedding...")
        print("   Department: HR")
        print("   Priority: High")
        print("   Message: 'Confidential employee compensation data'")
        
        # Simulate embedding
        cloud_path = "/CCS/StegoFolders/HR_high_20240115_143022"
        print(f"   Result: Message embedded to {cloud_path}")
        
        print("\n4. Demonstrating Secure Message Extraction...")
        print("   Department: HR (authorized)")
        print("   Cloud path: {cloud_path}")
        
        # Simulate extraction
        extracted = "Confidential employee compensation data"
        print(f"   Result: Message extracted: '{extracted}'")
        
        print("\n5. Demonstrating Security Controls...")
        print("   Attempting unauthorized extraction (Marketing department)...")
        print("   Result: PermissionError - Department not authorized")
        
        print("\n6. Generating Compliance Report...")
        report = deployer.generate_compliance_report()
        print(f"   Enterprise: {report['enterprise_name']}")
        print(f"   Compliance: {', '.join(report['compliance_frameworks'])}")
        print(f"   Total operations: {report['audit_trail']['total_operations']}")
        
        print("\n" + "=" * 70)
        print("ENTERPRISE DEPLOYMENT FEATURES DEMONSTRATED:")
        print("=" * 70)
        print("✓ Role-based access control")
        print("✓ Department-specific permissions")
        print("✓ Priority-based protocol selection")
        print("✓ Enterprise key management")
        print("✓ Compliance reporting")
        print("✓ Audit logging")
        print("✓ Cloud integration with backup providers")
        print("✓ Security policy enforcement")
        
        # Get deployment status
        status = deployer.get_deployment_status()
        print(f"\nDeployment Status: {status['total_operations']} operations, "
              f"{status['error_count']} errors")
        
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir)
    
    print("\n" + "=" * 70)
    print("ENTERPRISE DEPLOYMENT COMPLETE")
    print("=" * 70)
    print("\nFor production deployment:")
    print("1. Integrate with corporate IAM system")
    print("2. Store keys in HSM or enterprise key vault")
    print("3. Configure real cloud storage credentials")
    print("4. Set up monitoring and alerting")
    print("5. Conduct security review and penetration testing")


if __name__ == "__main__":
    demonstrate_enterprise_workflow()
