# OneDrive integration for CCS
# Implements cloud operations for Microsoft OneDrive

import os
import json
import time
import requests
from typing import List, Dict, Optional
from pathlib import Path

from msal import ConfidentialClientApplication, PublicClientApplication

from ..utils.error_handling import robust_cloud_operation

class OneDriveClient:
    """Client for Microsoft OneDrive/Graph API operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        
        # MSAL configuration
        self.client_id = self.config.get('client_id')
        self.client_secret = self.config.get('client_secret')
        self.tenant_id = self.config.get('tenant_id', 'common')
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        # Scopes for OneDrive access
        self.scopes = [
            'Files.ReadWrite',
            'Files.ReadWrite.All',
            'Sites.ReadWrite.All',
            'offline_access'  # For refresh tokens
        ]
        
        # Cache file for tokens
        self.token_cache_file = self.config.get('token_cache_file', 'onedrive_token_cache.json')
        
    def authenticate(self) -> bool:
        """Authenticate with Microsoft Graph API"""
        # Try to load cached tokens
        if os.path.exists(self.token_cache_file):
            with open(self.token_cache_file, 'r') as f:
                token_cache = json.load(f)
                self.access_token = token_cache.get('access_token')
                self.refresh_token = token_cache.get('refresh_token')
                self.token_expiry = token_cache.get('expiry_time')
        
        # Check if token is still valid
        if self.access_token and self.token_expiry:
            if time.time() < self.token_expiry - 300:  # 5 minute buffer
                return True
        
        # Need to get new tokens
        if self.client_secret:
            # Confidential client (web app/service)
            app = ConfidentialClientApplication(
                self.client_id,
                authority=self.authority,
                client_credential=self.client_secret
            )
        else:
            # Public client (desktop/mobile app)
            app = PublicClientApplication(
                self.client_id,
                authority=self.authority
            )
        
        # Try to get token from cache or refresh
        accounts = app.get_accounts()
        result = None
        
        if accounts:
            # Try to get token silently
            result = app.acquire_token_silent(self.scopes, account=accounts[0])
        
        if not result:
            # Need interactive login
            if self.client_secret:
                # Client credentials flow (non-interactive)
                result = app.acquire_token_for_client(scopes=self.scopes)
            else:
                # Device code flow for headless environments
                flow = app.initiate_device_flow(scopes=self.scopes)
                print(f"Please authenticate: {flow['message']}")
                result = app.acquire_token_by_device_flow(flow)
        
        if result and 'access_token' in result:
            self.access_token = result['access_token']
            self.refresh_token = result.get('refresh_token')
            
            # Calculate expiry time
            expires_in = result.get('expires_in', 3600)
            self.token_expiry = time.time() + expires_in
            
            # Save to cache
            token_cache = {
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'expiry_time': self.token_expiry
            }
            with open(self.token_cache_file, 'w') as f:
                json.dump(token_cache, f)
            
            return True
        
        return False
    
    def _make_request(self, method: str, endpoint: str, 
                     data: Optional[Dict] = None, 
                     headers: Optional[Dict] = None) -> Optional[Dict]:
        """Make authenticated request to Microsoft Graph API"""
        if not self.access_token and not self.authenticate():
            return None
        
        url = f"https://graph.microsoft.com/v1.0{endpoint}"
        
        request_headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        if headers:
            request_headers.update(headers)
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=request_headers)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=request_headers, json=data)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=request_headers, json=data)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=request_headers)
            elif method.upper() == 'PATCH':
                response = requests.patch(url, headers=request_headers, json=data)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            
            if response.status_code == 204:  # No content
                return {}
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            
            # Try to refresh token if it's an auth error
            if hasattr(e.response, 'status_code') and e.response.status_code == 401:
                print("Token expired, attempting refresh...")
                if self._refresh_token():
                    # Retry request with new token
                    return self._make_request(method, endpoint, data, headers)
            
            return None
    
    def _refresh_token(self) -> bool:
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            return False
        
        # This would normally use MSAL's refresh logic
        # Simplified version for demonstration
        token_data = {
            'client_id': self.client_id,
            'refresh_token': self.refresh_token,
            'grant_type': 'refresh_token',
            'scope': ' '.join(self.scopes)
        }
        
        if self.client_secret:
            token_data['client_secret'] = self.client_secret
        
        try:
            response = requests.post(
                f"{self.authority}/oauth2/v2.0/token",
                data=token_data
            )
            response.raise_for_status()
            result = response.json()
            
            self.access_token = result['access_token']
            self.refresh_token = result.get('refresh_token', self.refresh_token)
            
            expires_in = result.get('expires_in', 3600)
            self.token_expiry = time.time() + expires_in
            
            # Update cache
            token_cache = {
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'expiry_time': self.token_expiry
            }
            with open(self.token_cache_file, 'w') as f:
                json.dump(token_cache, f)
            
            return True
            
        except Exception as e:
            print(f"Token refresh failed: {e}")
            return False
    
    @robust_cloud_operation
    def list_files(self, folder_id: str = 'root') -> List[Dict]:
        """
        List files in a folder
        
        Args:
            folder_id: OneDrive folder ID ('root' for root folder)
            
        Returns:
            List of file metadata dictionaries
        """
        endpoint = f"/me/drive/items/{folder_id}/children"
        
        result = self._make_request('GET', endpoint)
        if not result:
            return []
        
        files = []
        for item in result.get('value', []):
            if 'file' in item:  # It's a file, not a folder
                files.append({
                    'id': item['id'],
                    'name': item['name'],
                    'size': item.get('size', 0),
                    'createdDateTime': item.get('createdDateTime'),
                    'lastModifiedDateTime': item.get('lastModifiedDateTime'),
                    'file': item.get('file', {})
                })
        
        return files
    
    @robust_cloud_operation
    def create_folder(self, name: str, parent_id: str = 'root') -> Optional[str]:
        """
        Create a new folder
        
        Args:
            name: Folder name
            parent_id: Parent folder ID
            
        Returns:
            Folder ID if successful, None otherwise
        """
        endpoint = f"/me/drive/items/{parent_id}/children"
        
        data = {
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename"
        }
        
        result = self._make_request('POST', endpoint, data)
        if result and 'id' in result:
            return result['id']
        
        return None
    
    @robust_cloud_operation
    def upload_file(self, local_path: str, remote_name: str = None,
                   folder_id: str = 'root') -> Optional[str]:
        """
        Upload a file to OneDrive
        
        Args:
            local_path: Local file path
            remote_name: Name in OneDrive (defaults to local filename)
            folder_id: Folder ID to upload to
            
        Returns:
            File ID if successful, None otherwise
        """
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")
        
        if remote_name is None:
            remote_name = os.path.basename(local_path)
        
        file_size = os.path.getsize(local_path)
        
        # Use different methods based on file size
        if file_size < 4 * 1024 * 1024:  # 4MB
            # Simple upload for small files
            return self._upload_small_file(local_path, remote_name, folder_id)
        else:
            # Resumable upload for large files
            return self._upload_large_file(local_path, remote_name, folder_id, file_size)
    
    def _upload_small_file(self, local_path: str, remote_name: str, 
                          folder_id: str) -> Optional[str]:
        """Upload small file (< 4MB)"""
        endpoint = f"/me/drive/items/{folder_id}:/{remote_name}:/content"
        
        headers = {
            'Content-Type': 'application/octet-stream'
        }
        
        with open(local_path, 'rb') as f:
            data = f.read()
        
        result = self._make_request('PUT', endpoint, data=data, headers=headers)
        if result and 'id' in result:
            return result['id']
        
        return None
    
    def _upload_large_file(self, local_path: str, remote_name: str,
                          folder_id: str, file_size: int) -> Optional[str]:
        """Upload large file using resumable upload"""
        # Create upload session
        endpoint = f"/me/drive/items/{folder_id}:/{remote_name}:/createUploadSession"
        
        data = {
            "item": {
                "@microsoft.graph.conflictBehavior": "rename"
            }
        }
        
        session_result = self._make_request('POST', endpoint, data)
        if not session_result or 'uploadUrl' not in session_result:
            return None
        
        upload_url = session_result['uploadUrl']
        
        # Upload in chunks
        chunk_size = 327680  # 320KB chunks recommended by Microsoft
        with open(local_path, 'rb') as f:
            start = 0
            
            while start < file_size:
                end = min(start + chunk_size, file_size) - 1
                chunk = f.read(chunk_size)
                
                headers = {
                    'Content-Length': str(len(chunk)),
                    'Content-Range': f"bytes {start}-{end}/{file_size}"
                }
                
                # Upload chunk
                response = requests.put(upload_url, headers=headers, data=chunk)
                
                if response.status_code not in [200, 201, 202]:
                    print(f"Chunk upload failed: {response.status_code}")
                    return None
                
                start = end + 1
        
        # Get file ID from completed upload
        file_info = response.json()
        return file_info.get('id')
    
    @robust_cloud_operation
    def download_file(self, file_id: str, local_path: str) -> bool:
        """
        Download a file from OneDrive
        
        Args:
            file_id: OneDrive file ID
            local_path: Local path to save file
            
        Returns:
            True if successful
        """
        endpoint = f"/me/drive/items/{file_id}/content"
        
        if not self.access_token and not self.authenticate():
            return False
        
        url = f"https://graph.microsoft.com/v1.0{endpoint}"
        headers = {'Authorization': f'Bearer {self.access_token}'}
        
        try:
            response = requests.get(url, headers=headers, stream=True)
            response.raise_for_status()
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return True
            
        except Exception as e:
            print(f"Download failed: {e}")
            return False
    
    @robust_cloud_operation
    def delete_file(self, file_id: str) -> bool:
        """
        Delete a file from OneDrive
        
        Args:
            file_id: OneDrive file ID
            
        Returns:
            True if successful
        """
        endpoint = f"/me/drive/items/{file_id}"
        
        result = self._make_request('DELETE', endpoint)
        return result is not None
    
    @robust_cloud_operation
    def get_file_metadata(self, file_id: str) -> Optional[Dict]:
        """
        Get metadata for a file
        
        Args:
            file_id: OneDrive file ID
            
        Returns:
            File metadata dictionary
        """
        endpoint = f"/me/drive/items/{file_id}"
        
        result = self._make_request('GET', endpoint)
        if result and 'file' in result:
            return {
                'id': result['id'],
                'name': result['name'],
                'size': result.get('size', 0),
                'createdDateTime': result.get('createdDateTime'),
                'lastModifiedDateTime': result.get('lastModifiedDateTime'),
                'file': result.get('file', {})
            }
        
        return None
    
    def get_folder_by_path(self, path: str) -> Optional[str]:
        """
        Get folder ID by path
        
        Args:
            path: Folder path
            
        Returns:
            Folder ID or None if not found
        """
        if path == '' or path == '/':
            return 'root'
        
        endpoint = f"/me/drive/root:{path}"
        
        result = self._make_request('GET', endpoint)
        if result and 'folder' in result:
            return result['id']
        
        return None
    
    def create_folder_structure(self, path: str) -> Optional[str]:
        """
        Create folder structure if it doesn't exist
        
        Args:
            path: Folder path to create
            
        Returns:
            Final folder ID
        """
        parts = [p for p in path.strip('/').split('/') if p]
        current_id = 'root'
        
        for part in parts:
            # Check if folder exists
            check_endpoint = f"/me/drive/items/{current_id}:/{part}"
            result = self._make_request('GET', check_endpoint)
            
            if result and 'folder' in result:
                current_id = result['id']
            else:
                # Create folder
                new_folder_id = self.create_folder(part, current_id)
                if not new_folder_id:
                    return None
                current_id = new_folder_id
        
        return current_id


class CCSOneDriveManager:
    """CCS-specific OneDrive operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.client = OneDriveClient(config)
        self.config = config or {}
        
        # CCS-specific settings
        self.base_folder = self.config.get('base_folder', 'CCS')
        self.cover_folder_prefix = self.config.get('cover_folder_prefix', 'CoverFolder_')
        self.stego_folder_prefix = self.config.get('stego_folder_prefix', 'StegoFolder_')
        
    def setup_ccs_structure(self) -> Dict[str, str]:
        """
        Setup CCS folder structure in OneDrive
        
        Returns:
            Dictionary mapping folder names to folder IDs
        """
        if not self.client.authenticate():
            raise RuntimeError("Failed to authenticate with OneDrive")
        
        folder_ids = {}
        
        # Create base folder
        base_id = self.client.create_folder_structure(self.base_folder)
        folder_ids['base'] = base_id
        
        # Create subfolders
        subfolders = [
            'CoverFolders',
            'StegoFolders',
            'Backups',
            'Config'
        ]
        
        for folder in subfolders:
            folder_path = f"{self.base_folder}/{folder}"
            folder_id = self.client.create_folder_structure(folder_path)
            folder_ids[folder] = folder_id
        
        return folder_ids
    
    def upload_cover_folder(self, local_folder: str, 
                           remote_name: str = None) -> Optional[str]:
        """
        Upload a cover folder to OneDrive
        
        Args:
            local_folder: Local folder path
            remote_name: Remote folder name
            
        Returns:
            Folder ID if successful
        """
        if not remote_name:
            remote_name = os.path.basename(local_folder)
        
        # Create remote folder
        folder_path = f"{self.base_folder}/CoverFolders/{remote_name}"
        folder_id = self.client.create_folder_structure(folder_path)
        
        if not folder_id:
            return None
        
        # Upload all files in the folder
        for filename in os.listdir(local_folder):
            local_path = os.path.join(local_folder, filename)
            if os.path.isfile(local_path):
                self.client.upload_file(local_path, folder_id=folder_id)
        
        return folder_id
    
    def download_cover_folder(self, folder_id: str, 
                             local_path: str) -> bool:
        """
        Download a cover folder from OneDrive
        
        Args:
            folder_id: OneDrive folder ID
            local_path: Local path to save folder
            
        Returns:
            True if successful
        """
        # Create local directory
        os.makedirs(local_path, exist_ok=True)
        
        # List files in folder
        files = self.client.list_files(folder_id)
        
        # Download each file
        for file in files:
            if 'file' in file:
                remote_path = os.path.join(local_path, file['name'])
                self.client.download_file(file['id'], remote_path)
        
        return True
    
    def get_folder_files(self, folder_id: str) -> List[Dict]:
        """
        Get list of files in a folder
        
        Args:
            folder_id: OneDrive folder ID
            
        Returns:
            List of file metadata
        """
        return self.client.list_files(folder_id)
    
    def create_stego_folder(self, stego_name: str = None) -> Optional[str]:
        """
        Create a stego-folder in OneDrive
        
        Args:
            stego_name: Name for stego-folder
            
        Returns:
            Folder ID if successful
        """
        if not stego_name:
            timestamp = int(time.time())
            stego_name = f"{self.stego_folder_prefix}{timestamp}"
        
        folder_path = f"{self.base_folder}/StegoFolders/{stego_name}"
        return self.client.create_folder_structure(folder_path)
    
    def copy_to_stego_folder(self, source_file_id: str, 
                            stego_folder_id: str) -> bool:
        """
        Copy a file to stego-folder
        
        Args:
            source_file_id: Source file ID
            stego_folder_id: Stego-folder ID
            
        Returns:
            True if successful
        """
        # Get file metadata
        metadata = self.client.get_file_metadata(source_file_id)
        if not metadata:
            return False
        
        # Copy file using Graph API copy action
        endpoint = f"/me/drive/items/{source_file_id}/copy"
        
        data = {
            "parentReference": {
                "id": stego_folder_id
            },
            "name": metadata['name']
        }
        
        result = self.client._make_request('POST', endpoint, data)
        return result is not None
