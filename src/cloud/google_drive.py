# Google Drive integration for CCS
# Implements cloud operations for Google Drive

import os
import io
import json
import time
from typing import List, Dict, Optional, BinaryIO
from pathlib import Path

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

from ..utils.error_handling import robust_cloud_operation

class GoogleDriveClient:
    """Client for Google Drive operations"""
    
    # If modifying these scopes, delete the file token.json
    SCOPES = [
        'https://www.googleapis.com/auth/drive.file',  # Per-file access
        'https://www.googleapis.com/auth/drive.metadata.readonly'
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.service = None
        self.credentials = None
        self.token_file = self.config.get('token_file', 'token.json')
        self.credentials_file = self.config.get('credentials_file', 'credentials.json')
        
    def authenticate(self) -> bool:
        """Authenticate with Google Drive API"""
        try:
            creds = None
            
            # Token file stores the user's access and refresh tokens
            if os.path.exists(self.token_file):
                with open(self.token_file, 'r') as token:
                    creds = Credentials.from_authorized_user_info(
                        json.load(token), self.SCOPES
                    )
            
            # If there are no (valid) credentials available, let the user log in
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    if not os.path.exists(self.credentials_file):
                        raise FileNotFoundError(
                            f"Credentials file not found: {self.credentials_file}"
                        )
                    
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_file, self.SCOPES
                    )
                    creds = flow.run_local_server(port=0)
                
                # Save the credentials for the next run
                with open(self.token_file, 'w') as token:
                    token.write(creds.to_json())
            
            self.credentials = creds
            self.service = build('drive', 'v3', credentials=creds)
            return True
            
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False
    
    @robust_cloud_operation
    def list_files(self, folder_id: str = 'root', 
                  query: str = None) -> List[Dict]:
        """
        List files in a folder
        
        Args:
            folder_id: Google Drive folder ID ('root' for root folder)
            query: Optional query to filter files
            
        Returns:
            List of file metadata dictionaries
        """
        if not self.service:
            self.authenticate()
        
        # Build query
        base_query = f"'{folder_id}' in parents and trashed = false"
        if query:
            full_query = f"{base_query} and {query}"
        else:
            full_query = base_query
        
        results = []
        page_token = None
        
        while True:
            try:
                response = self.service.files().list(
                    q=full_query,
                    spaces='drive',
                    fields='nextPageToken, files(id, name, mimeType, size, '
                           'createdTime, modifiedTime, md5Checksum)',
                    pageToken=page_token,
                    pageSize=1000  # Max page size
                ).execute()
                
                files = response.get('files', [])
                results.extend(files)
                
                page_token = response.get('nextPageToken', None)
                if page_token is None:
                    break
                    
            except HttpError as error:
                print(f"An error occurred: {error}")
                break
        
        return results
    
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
        if not self.service:
            self.authenticate()
        
        file_metadata = {
            'name': name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id]
        }
        
        try:
            folder = self.service.files().create(
                body=file_metadata,
                fields='id'
            ).execute()
            
            return folder.get('id')
            
        except HttpError as error:
            print(f"An error occurred creating folder: {error}")
            return None
    
    @robust_cloud_operation
    def upload_file(self, local_path: str, remote_name: str = None,
                   folder_id: str = 'root', mime_type: str = None) -> Optional[str]:
        """
        Upload a file to Google Drive
        
        Args:
            local_path: Local file path
            remote_name: Name in Google Drive (defaults to local filename)
            folder_id: Folder ID to upload to
            mime_type: MIME type of the file
            
        Returns:
            File ID if successful, None otherwise
        """
        if not self.service:
            self.authenticate()
        
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")
        
        if remote_name is None:
            remote_name = os.path.basename(local_path)
        
        if mime_type is None:
            # Try to guess MIME type from extension
            import mimetypes
            mime_type, _ = mimetypes.guess_type(local_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'
        
        file_metadata = {
            'name': remote_name,
            'parents': [folder_id]
        }
        
        media = MediaFileUpload(
            local_path,
            mimetype=mime_type,
            resumable=True
        )
        
        try:
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            return file.get('id')
            
        except HttpError as error:
            print(f"An error occurred uploading file: {error}")
            return None
    
    @robust_cloud_operation
    def download_file(self, file_id: str, local_path: str) -> bool:
        """
        Download a file from Google Drive
        
        Args:
            file_id: Google Drive file ID
            local_path: Local path to save file
            
        Returns:
            True if successful, False otherwise
        """
        if not self.service:
            self.authenticate()
        
        try:
            request = self.service.files().get_media(fileId=file_id)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            with open(local_path, 'wb') as f:
                downloader = MediaIoBaseDownload(f, request)
                done = False
                
                while not done:
                    status, done = downloader.next_chunk()
                    if status:
                        print(f"Download {int(status.progress() * 100)}%")
            
            return True
            
        except HttpError as error:
            print(f"An error occurred downloading file: {error}")
            return False
    
    @robust_cloud_operation
    def delete_file(self, file_id: str) -> bool:
        """
        Delete a file from Google Drive
        
        Args:
            file_id: Google Drive file ID
            
        Returns:
            True if successful, False otherwise
        """
        if not self.service:
            self.authenticate()
        
        try:
            self.service.files().delete(fileId=file_id).execute()
            return True
            
        except HttpError as error:
            print(f"An error occurred deleting file: {error}")
            return False
    
    @robust_cloud_operation
    def get_file_metadata(self, file_id: str) -> Optional[Dict]:
        """
        Get metadata for a file
        
        Args:
            file_id: Google Drive file ID
            
        Returns:
            File metadata dictionary
        """
        if not self.service:
            self.authenticate()
        
        try:
            file = self.service.files().get(
                fileId=file_id,
                fields='id, name, mimeType, size, createdTime, '
                       'modifiedTime, md5Checksum, parents'
            ).execute()
            
            return file
            
        except HttpError as error:
            print(f"An error occurred getting file metadata: {error}")
            return None
    
    @robust_cloud_operation
    def search_files(self, query: str) -> List[Dict]:
        """
        Search for files
        
        Args:
            query: Search query
            
        Returns:
            List of file metadata dictionaries
        """
        if not self.service:
            self.authenticate()
        
        results = []
        page_token = None
        
        while True:
            try:
                response = self.service.files().list(
                    q=query,
                    spaces='drive',
                    fields='nextPageToken, files(id, name, mimeType, size, '
                           'createdTime, modifiedTime)',
                    pageToken=page_token,
                    pageSize=1000
                ).execute()
                
                files = response.get('files', [])
                results.extend(files)
                
                page_token = response.get('nextPageToken', None)
                if page_token is None:
                    break
                    
            except HttpError as error:
                print(f"An error occurred: {error}")
                break
        
        return results
    
    def get_folder_by_path(self, path: str) -> Optional[str]:
        """
        Get folder ID by path
        
        Args:
            path: Folder path (e.g., '/CCS/CoverFolders/F0')
            
        Returns:
            Folder ID or None if not found
        """
        if not self.service:
            self.authenticate()
        
        parts = [p for p in path.strip('/').split('/') if p]
        current_id = 'root'
        
        for part in parts:
            query = f"name = '{part}' and '{current_id}' in parents " \
                    f"and mimeType = 'application/vnd.google-apps.folder' " \
                    f"and trashed = false"
            
            results = self.search_files(query)
            
            if not results:
                return None
            
            current_id = results[0]['id']
        
        return current_id
    
    @robust_cloud_operation
    def create_folder_structure(self, path: str) -> str:
        """
        Create folder structure if it doesn't exist
        
        Args:
            path: Folder path to create
            
        Returns:
            Final folder ID
        """
        if not self.service:
            self.authenticate()
        
        parts = [p for p in path.strip('/').split('/') if p]
        current_id = 'root'
        
        for part in parts:
            query = f"name = '{part}' and '{current_id}' in parents " \
                    f"and mimeType = 'application/vnd.google-apps.folder' " \
                    f"and trashed = false"
            
            results = self.search_files(query)
            
            if results:
                current_id = results[0]['id']
            else:
                current_id = self.create_folder(part, current_id)
                if not current_id:
                    raise RuntimeError(f"Failed to create folder: {part}")
        
        return current_id


class CCSGoogleDriveManager:
    """CCS-specific Google Drive operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.client = GoogleDriveClient(config)
        self.config = config or {}
        
        # CCS-specific settings
        self.base_folder = self.config.get('base_folder', 'CCS')
        self.cover_folder_prefix = self.config.get('cover_folder_prefix', 'CoverFolder_')
        self.stego_folder_prefix = self.config.get('stego_folder_prefix', 'StegoFolder_')
        
    def setup_ccs_structure(self) -> Dict[str, str]:
        """
        Setup CCS folder structure in Google Drive
        
        Returns:
            Dictionary mapping folder names to folder IDs
        """
        if not self.client.authenticate():
            raise RuntimeError("Failed to authenticate with Google Drive")
        
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
        Upload a cover folder to Google Drive
        
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
        Download a cover folder from Google Drive
        
        Args:
            folder_id: Google Drive folder ID
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
            if file['mimeType'] != 'application/vnd.google-apps.folder':
                remote_path = os.path.join(local_path, file['name'])
                self.client.download_file(file['id'], remote_path)
        
        return True
    
    def get_folder_files(self, folder_id: str) -> List[Dict]:
        """
        Get list of files in a folder
        
        Args:
            folder_id: Google Drive folder ID
            
        Returns:
            List of file metadata
        """
        return self.client.list_files(folder_id)
    
    def create_stego_folder(self, stego_name: str = None) -> Optional[str]:
        """
        Create a stego-folder in Google Drive
        
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
        if not self.client.service:
            self.client.authenticate()
        
        try:
            # Copy file to new location
            copied_file = {'parents': [stego_folder_id]}
            
            self.client.service.files().copy(
                fileId=source_file_id,
                body=copied_file
            ).execute()
            
            return True
            
        except HttpError as error:
            print(f"An error occurred copying file: {error}")
            return False
