# Dropbox integration for CCS
# Implements cloud operations for Dropbox

import os
import json
import time
import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError
from typing import List, Dict, Optional, BinaryIO
from pathlib import Path

from ..utils.error_handling import robust_cloud_operation

class DropboxClient:
    """Client for Dropbox operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.client = None
        self.access_token = self.config.get('access_token')
        self.app_key = self.config.get('app_key')
        self.app_secret = self.config.get('app_secret')
        
        if not self.access_token and (self.app_key and self.app_secret):
            # Could implement OAuth flow here
            pass
    
    def authenticate(self) -> bool:
        """Authenticate with Dropbox"""
        if not self.access_token:
            if self.app_key and self.app_secret:
                # TODO: Implement OAuth flow
                print("OAuth flow not implemented in this example")
                return False
            else:
                print("No access token or app credentials provided")
                return False
        
        try:
            self.client = dropbox.Dropbox(self.access_token)
            # Test authentication
            self.client.users_get_current_account()
            return True
            
        except AuthError as e:
            print(f"Dropbox authentication failed: {e}")
            return False
        except Exception as e:
            print(f"Error connecting to Dropbox: {e}")
            return False
    
    @robust_cloud_operation
    def list_files(self, path: str = '') -> List[Dict]:
        """
        List files in a folder
        
        Args:
            path: Dropbox path
            
        Returns:
            List of file metadata dictionaries
        """
        if not self.client:
            if not self.authenticate():
                return []
        
        try:
            if path and not path.startswith('/'):
                path = '/' + path
            
            result = self.client.files_list_folder(path)
            files = []
            
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    files.append({
                        'name': entry.name,
                        'path_lower': entry.path_lower,
                        'size': entry.size,
                        'client_modified': entry.client_modified,
                        'server_modified': entry.server_modified,
                        'content_hash': entry.content_hash if hasattr(entry, 'content_hash') else None
                    })
            
            # Handle pagination
            while result.has_more:
                result = self.client.files_list_folder_continue(result.cursor)
                for entry in result.entries:
                    if isinstance(entry, dropbox.files.FileMetadata):
                        files.append({
                            'name': entry.name,
                            'path_lower': entry.path_lower,
                            'size': entry.size,
                            'client_modified': entry.client_modified,
                            'server_modified': entry.server_modified,
                            'content_hash': entry.content_hash if hasattr(entry, 'content_hash') else None
                        })
            
            return files
            
        except ApiError as e:
            if e.error.is_path() and e.error.get_path().is_not_found():
                print(f"Path not found: {path}")
            else:
                print(f"API error listing files: {e}")
            return []
        except Exception as e:
            print(f"Error listing files: {e}")
            return []
    
    @robust_cloud_operation
    def upload_file(self, local_path: str, remote_path: str, 
                   overwrite: bool = True) -> bool:
        """
        Upload a file to Dropbox
        
        Args:
            local_path: Local file path
            remote_path: Remote path in Dropbox
            overwrite: Whether to overwrite existing file
            
        Returns:
            True if successful
        """
        if not self.client:
            if not self.authenticate():
                return False
        
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")
        
        if not remote_path.startswith('/'):
            remote_path = '/' + remote_path
        
        mode = WriteMode('overwrite' if overwrite else 'add')
        
        try:
            file_size = os.path.getsize(local_path)
            
            # Use chunked upload for large files (> 150MB)
            CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks
            
            if file_size <= CHUNK_SIZE:
                # Small file, upload in one go
                with open(local_path, 'rb') as f:
                    data = f.read()
                
                self.client.files_upload(data, remote_path, mode=mode)
                
            else:
                # Large file, use chunked upload
                with open(local_path, 'rb') as f:
                    upload_session_start_result = self.client.files_upload_session_start(
                        f.read(CHUNK_SIZE)
                    )
                    cursor = dropbox.files.UploadSessionCursor(
                        session_id=upload_session_start_result.session_id,
                        offset=f.tell()
                    )
                    commit = dropbox.files.CommitInfo(
                        path=remote_path,
                        mode=mode
                    )
                    
                    while f.tell() < file_size:
                        if (file_size - f.tell()) <= CHUNK_SIZE:
                            self.client.files_upload_session_finish(
                                f.read(CHUNK_SIZE),
                                cursor,
                                commit
                            )
                        else:
                            self.client.files_upload_session_append_v2(
                                f.read(CHUNK_SIZE),
                                cursor
                            )
                            cursor.offset = f.tell()
            
            return True
            
        except ApiError as e:
            print(f"API error uploading file: {e}")
            return False
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
    
    @robust_cloud_operation
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download a file from Dropbox
        
        Args:
            remote_path: Remote path in Dropbox
            local_path: Local path to save file
            
        Returns:
            True if successful
        """
        if not self.client:
            if not self.authenticate():
                return False
        
        if not remote_path.startswith('/'):
            remote_path = '/' + remote_path
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            metadata, response = self.client.files_download(remote_path)
            
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            return True
            
        except ApiError as e:
            print(f"API error downloading file: {e}")
            return False
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
    
    @robust_cloud_operation
    def create_folder(self, path: str) -> bool:
        """
        Create a folder in Dropbox
        
        Args:
            path: Folder path
            
        Returns:
            True if successful
        """
        if not self.client:
            if not self.authenticate():
                return False
        
        if not path.startswith('/'):
            path = '/' + path
        
        try:
            self.client.files_create_folder_v2(path)
            return True
            
        except ApiError as e:
            # Folder might already exist
            if e.error.is_path() and e.error.get_path().is_conflict():
                return True
            print(f"API error creating folder: {e}")
            return False
        except Exception as e:
            print(f"Error creating folder: {e}")
            return False
    
    @robust_cloud_operation
    def delete_file(self, path: str) -> bool:
        """
        Delete a file or folder from Dropbox
        
        Args:
            path: Path to delete
            
        Returns:
            True if successful
        """
        if not self.client:
            if not self.authenticate():
                return False
        
        if not path.startswith('/'):
            path = '/' + path
        
        try:
            self.client.files_delete_v2(path)
            return True
            
        except ApiError as e:
            print(f"API error deleting file: {e}")
            return False
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False
    
    @robust_cloud_operation
    def get_file_metadata(self, path: str) -> Optional[Dict]:
        """
        Get metadata for a file
        
        Args:
            path: File path
            
        Returns:
            File metadata dictionary
        """
        if not self.client:
            if not self.authenticate():
                return None
        
        if not path.startswith('/'):
            path = '/' + path
        
        try:
            metadata = self.client.files_get_metadata(path)
            
            if isinstance(metadata, dropbox.files.FileMetadata):
                return {
                    'name': metadata.name,
                    'path_lower': metadata.path_lower,
                    'size': metadata.size,
                    'client_modified': metadata.client_modified,
                    'server_modified': metadata.server_modified,
                    'content_hash': metadata.content_hash if hasattr(metadata, 'content_hash') else None
                }
            else:
                return None
                
        except ApiError as e:
            print(f"API error getting metadata: {e}")
            return None
        except Exception as e:
            print(f"Error getting metadata: {e}")
            return None
    
    def create_folder_structure(self, path: str) -> bool:
        """
        Create folder structure if it doesn't exist
        
        Args:
            path: Folder path to create
            
        Returns:
            True if successful
        """
        if not self.client:
            if not self.authenticate():
                return False
        
        parts = [p for p in path.strip('/').split('/') if p]
        current_path = ''
        
        for part in parts:
            current_path = f"{current_path}/{part}"
            self.create_folder(current_path)
        
        return True


class CCSDropboxManager:
    """CCS-specific Dropbox operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.client = DropboxClient(config)
        self.config = config or {}
        
        # CCS-specific settings
        self.base_folder = self.config.get('base_folder', '/CCS')
        self.cover_folder_prefix = self.config.get('cover_folder_prefix', 'CoverFolder_')
        self.stego_folder_prefix = self.config.get('stego_folder_prefix', 'StegoFolder_')
        
    def setup_ccs_structure(self) -> Dict[str, str]:
        """
        Setup CCS folder structure in Dropbox
        
        Returns:
            Dictionary mapping folder names to paths
        """
        if not self.client.authenticate():
            raise RuntimeError("Failed to authenticate with Dropbox")
        
        folder_paths = {}
        
        # Create base folder
        self.client.create_folder_structure(self.base_folder)
        folder_paths['base'] = self.base_folder
        
        # Create subfolders
        subfolders = [
            'CoverFolders',
            'StegoFolders',
            'Backups',
            'Config'
        ]
        
        for folder in subfolders:
            folder_path = f"{self.base_folder}/{folder}"
            self.client.create_folder_structure(folder_path)
            folder_paths[folder] = folder_path
        
        return folder_paths
    
    def upload_cover_folder(self, local_folder: str, 
                           remote_name: str = None) -> bool:
        """
        Upload a cover folder to Dropbox
        
        Args:
            local_folder: Local folder path
            remote_name: Remote folder name
            
        Returns:
            True if successful
        """
        if not remote_name:
            remote_name = os.path.basename(local_folder)
        
        remote_path = f"{self.base_folder}/CoverFolders/{remote_name}"
        
        # Create remote folder
        self.client.create_folder_structure(remote_path)
        
        # Upload all files in the folder
        for filename in os.listdir(local_folder):
            local_path = os.path.join(local_folder, filename)
            if os.path.isfile(local_path):
                file_remote_path = f"{remote_path}/{filename}"
                if not self.client.upload_file(local_path, file_remote_path):
                    return False
        
        return True
    
    def download_cover_folder(self, remote_path: str, 
                             local_path: str) -> bool:
        """
        Download a cover folder from Dropbox
        
        Args:
            remote_path: Remote folder path
            local_path: Local path to save folder
            
        Returns:
            True if successful
        """
        # Create local directory
        os.makedirs(local_path, exist_ok=True)
        
        # List files in folder
        files = self.client.list_files(remote_path)
        
        # Download each file
        for file in files:
            file_remote_path = file['path_lower']
            file_local_path = os.path.join(local_path, file['name'])
            if not self.client.download_file(file_remote_path, file_local_path):
                return False
        
        return True
    
    def get_folder_files(self, folder_path: str) -> List[Dict]:
        """
        Get list of files in a folder
        
        Args:
            folder_path: Dropbox folder path
            
        Returns:
            List of file metadata
        """
        return self.client.list_files(folder_path)
    
    def create_stego_folder(self, stego_name: str = None) -> Optional[str]:
        """
        Create a stego-folder in Dropbox
        
        Args:
            stego_name: Name for stego-folder
            
        Returns:
            Folder path if successful
        """
        if not stego_name:
            timestamp = int(time.time())
            stego_name = f"{self.stego_folder_prefix}{timestamp}"
        
        folder_path = f"{self.base_folder}/StegoFolders/{stego_name}"
        
        if self.client.create_folder_structure(folder_path):
            return folder_path
        
        return None
    
    def copy_to_stego_folder(self, source_file_path: str, 
                            stego_folder_path: str) -> bool:
        """
        Copy a file to stego-folder
        
        Args:
            source_file_path: Source file path
            stego_folder_path: Stego-folder path
            
        Returns:
            True if successful
        """
        if not self.client.client:
            if not self.client.authenticate():
                return False
        
        try:
            # Get source file name
            source_name = os.path.basename(source_file_path)
            dest_path = f"{stego_folder_path}/{source_name}"
            
            # Copy by downloading and re-uploading
            # Note: Dropbox API v2 doesn't have a direct copy method for files across folders
            temp_path = f"/tmp/{source_name}"
            
            if self.client.download_file(source_file_path, temp_path):
                if self.client.upload_file(temp_path, dest_path):
                    os.remove(temp_path)
                    return True
            
            return False
            
        except Exception as e:
            print(f"Error copying file: {e}")
            return False
