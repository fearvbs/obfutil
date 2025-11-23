import os
import json
import struct
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional

from obfutil.crypto.encryption import encrypt_data, decrypt_data
from obfutil.utils.logger import get_logger
from obfutil.config import VAULTS_DIR

class VaultContainer:
    def __init__(self, vault_path: str):
        # if path is not absolute - save in VAULTS_DIR
        vault_path = Path(vault_path)
        if not vault_path.is_absolute():
            vault_path = VAULTS_DIR / vault_path
            self.vault_path = vault_path
            self.metadata = {}
            self.file_table: Dict[str, dict] = {}
            self.log = get_logger("VAULT_CONTAINER")
            self.decrypted_data = None
            self.file_data_offset = 0
            self.is_open = False
            self.failed_attempts = 0
            self.last_attempt_time = 0
        
    def create(self, size_mb: int, password: str = None, key: bytes = None):
        """Create new vault container"""
        try:
            self.log.info(f"Creating vault container: {self.vault_path} ({size_mb}MB)")
            
            # Ensure directory exists
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create metadata with correct date
            current_time = time.time()
            self.metadata = {
                'version': '1.0',
                'size_bytes': size_mb * 1024 * 1024,
                'created_at': current_time,
                'created_at_str': time.strftime('%Y-%m-%d %H:%M:%S'),
                'file_count': 0,
                'format': 'obfutil_vault',
                'file_table_offset': 0
            }
            
            # Initialize empty file table
            self.file_table = {}
            
            # Create header and empty space
            header = self._create_header()
            file_table_data = self._save_file_table()
            
            # Calculate available space
            header_size = len(header)
            file_table_size = len(file_table_data) + 4  # +4 for table size
            available_space = size_mb * 1024 * 1024 - header_size - file_table_size
            
            if available_space < 0:
                self.log.error("Vault size too small")
                return False
                
            empty_data = b'\x00' * available_space
            
            # Create structure: [header][file_table_size][file_table_data][file_data]
            vault_data = (
                header +
                struct.pack('>I', len(file_table_data)) +
                file_table_data +
                empty_data
            )
            
            self.log.info(f"Encrypting vault data ({len(vault_data)} bytes)")
            
            # Encrypt entire container
            if key:
                encrypted = encrypt_data(vault_data, key=key)
            else:
                encrypted = encrypt_data(vault_data, password=password)
                
            # Write file
            self.vault_path.write_bytes(encrypted)
            self.log.info(f"Vault container created successfully: {self.vault_path}")
            return True
            
        except Exception as e:
            self.log.error(f"Failed to create vault container: {e}")
            return False
    
    def _create_header(self) -> bytes:
        """Create container header"""
        try:
            metadata_json = json.dumps(self.metadata).encode('utf-8')
            header = struct.pack('>I', len(metadata_json)) + metadata_json
            return header
        except Exception as e:
            self.log.error(f"Failed to create vault header: {e}")
            raise
    
    def _read_header(self, data: bytes) -> bool:
        """Read container header"""
        try:
            metadata_len = struct.unpack('>I', data[:4])[0]
            metadata_json = data[4:4 + metadata_len]
            self.metadata = json.loads(metadata_json.decode('utf-8'))
            return True
        except Exception as e:
            self.log.error(f"Failed to read vault header: {e}")
            return False
    
    def open(self, password: str = None, key: bytes = None) -> bool:
        """Open existing vault with brute force protection"""
        try:
            # Brute force protection - delay after failed attempts
            current_time = time.time()
            if self.failed_attempts >= 3:
                time_since_last_attempt = current_time - self.last_attempt_time
                if time_since_last_attempt < (2 ** self.failed_attempts):  # Exponential delay
                    wait_time = (2 ** self.failed_attempts) - time_since_last_attempt
                    self.log.warning(f"Too many failed attempts. Waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)
            
            if not self.vault_path.exists():
                self.log.error(f"Vault file not found: {self.vault_path}")
                return False
                
            self.log.info(f"Opening vault: {self.vault_path}")
            encrypted_data = self.vault_path.read_bytes()
            
            # IMPORTANT: Check that at least one authentication method is provided
            if password is None and key is None:
                self.log.error("No authentication method provided")
                self.failed_attempts += 1
                self.last_attempt_time = time.time()
                return False
            
            try:
                if key:
                    decrypted = decrypt_data(encrypted_data, key=key)
                else:
                    decrypted = decrypt_data(encrypted_data, password=password)
            except Exception as e:
                self.log.error(f"Failed to decrypt vault: {e}")
                self.failed_attempts += 1
                self.last_attempt_time = time.time()
                return False

            self.decrypted_data = decrypted
                
            success = self._read_header(decrypted)
            if success:
                self.log.info(f"Vault opened successfully")
                self.is_open = True
                self.failed_attempts = 0  # Reset counter on successful opening
                return self._load_file_table(decrypted)
            else:
                self.log.error(f"Failed to open vault: invalid header")
                self.failed_attempts += 1
                self.last_attempt_time = time.time()
                return False
                
        except Exception as e:
            self.log.error(f"Error opening vault: {e}")
            self.failed_attempts += 1
            self.last_attempt_time = time.time()
            return False

    def _load_file_table(self, decrypted_data: bytes) -> bool:
        """Load file table from data"""
        try:
            # Position after header
            metadata_len = struct.unpack('>I', decrypted_data[:4])[0]
            header_size = 4 + metadata_len
            
            # Read file table size
            file_table_size = struct.unpack('>I', decrypted_data[header_size:header_size+4])[0]
            
            # Read file table data
            file_table_start = header_size + 4
            file_table_end = file_table_start + file_table_size
            file_table_json = decrypted_data[file_table_start:file_table_end]
            
            # Calculate file data offset
            self.file_data_offset = file_table_end
            
            if file_table_json:
                file_table_data = json.loads(file_table_json.decode('utf-8'))
                self.file_table = file_table_data.get('files', {})
                self.log.info(f"Loaded file table with {len(self.file_table)} files")
                return True
            else:
                self.file_table = {}
                self.log.info("File table is empty")
                return True
                
        except Exception as e:
            self.log.error(f"Failed to load file table: {e}")
            self.file_table = {}
            return False

    def _save_file_table(self) -> bytes:
        """Save file table"""
        try:
            file_table_data = {
                'files': self.file_table,
                'timestamp': time.time(),
                'file_count': len(self.file_table)
            }
            file_table_json = json.dumps(file_table_data, indent=2).encode('utf-8')
            return file_table_json
        except Exception as e:
            self.log.error(f"Failed to save file table: {e}")
            return b''

    def add_file(self, file_path: Path, internal_path: str, password: str = None, key: bytes = None) -> bool:
        """Add file to vault"""
        try:
            if not file_path.exists():
                self.log.error(f"Source file not found: {file_path}")
                return False

            # Read file data
            file_data = file_path.read_bytes()
            file_size = len(file_data)

            self.log.info(f"Adding file to vault: {internal_path} ({file_size} bytes)")

            # Update file table
            self.file_table[internal_path] = {
                'size': file_size,
                'added_at': time.time(),
                'original_name': file_path.name,
                'internal_path': internal_path,
                'offset': 0,  # Will be updated in _rewrite_vault_with_data
                'hash': self._calculate_hash(file_data)
            }

            # IMPORTANT: UPDATE FILE COUNT IN METADATA
            self.metadata['file_count'] = len(self.file_table)

            # Re-encrypt vault with new data
            success = self._rewrite_vault_with_data(file_data, password, key)
            if success:
                self.log.info(f"File {internal_path} added successfully to vault")
            return success

        except Exception as e:
            self.log.error(f"Failed to add file to vault: {e}")
            return False

    def extract_file(self, internal_path: str, output_path: Path, password: str = None, key: bytes = None) -> bool:
        """Extract file from vault"""
        try:
            self.log.info(f"Starting file extraction: {internal_path}")
        
            if internal_path not in self.file_table:
                self.log.error(f"File '{internal_path}' not found in file table")
                return False

            file_info = self.file_table[internal_path]
            self.log.info(f"Extracting file: {internal_path} (size: {file_info['size']} bytes, offset: {file_info['offset']})")
        
            # If vault not open, open it
            if not self.is_open or not self.decrypted_data:
                self.log.info("Vault not open, opening for extraction")
                if not self.open(password, key):
                    self.log.error("Failed to open vault for extraction")
                    return False
        
            # Check data boundaries
            if file_info['offset'] + file_info['size'] > len(self.decrypted_data):
                self.log.error(f"File data out of bounds: offset={file_info['offset']}, size={file_info['size']}, total_data={len(self.decrypted_data)}")
                return False
            
            # Extract file data
            file_data = self.decrypted_data[file_info['offset']:file_info['offset'] + file_info['size']]
        
            # Check integrity
            file_hash = self._calculate_hash(file_data)
            expected_hash = file_info['hash']
        
            if file_hash != expected_hash:
                self.log.error(f"File integrity check failed")
                return False
        
            # Create directory for output file
            output_path.parent.mkdir(parents=True, exist_ok=True)
        
            # Write actual file data
            output_path.write_bytes(file_data)
            self.log.info(f"File successfully written to: {output_path}")
        
            return True
        
        except Exception as e:
            self.log.error(f"Failed to extract file from vault: {str(e)}")
            return False

    def _calculate_hash(self, data: bytes) -> str:
        """Calculate file data hash"""
        return hashlib.sha256(data).hexdigest()

    def list_files(self) -> List[str]:
        """Return list of files in vault"""
        files = list(self.file_table.keys())
        self.log.info(f"Listed {len(files)} files from vault")
        return files

    def remove_file(self, internal_path: str, password: str = None, key: bytes = None) -> bool:
        """Remove file from vault"""
        try:
            if internal_path not in self.file_table:
                self.log.error(f"File not found in vault: {internal_path}")
                return False

            file_info = self.file_table[internal_path]
            self.log.info(f"Removing file from vault: {internal_path} ({file_info['size']} bytes)")
            
            # Remove from file table
            del self.file_table[internal_path]
            
            # Update file count
            self.metadata['file_count'] = len(self.file_table)
            
            # Re-encrypt vault without removed file
            success = self._rewrite_vault_with_data(None, password, key)
            if success:
                self.log.info(f"File {internal_path} removed successfully from vault")
            return success
            
        except Exception as e:
            self.log.error(f"Failed to remove file from vault: {e}")
            return False

    def _rewrite_vault_with_data(self, new_file_data: bytes = None, password: str = None, key: bytes = None) -> bool:
        """Rewrite vault with updated data and file table"""
        try:
            # Create new header
            header = self._create_header()
        
            # Save file table
            file_table_data = self._save_file_table()
            file_table_size = len(file_table_data)
        
            # CALCULATE NEW OFFSETS FOR ALL FILES
            current_offset = len(header) + 4 + file_table_size  # header + table_size + table_data
            all_file_data = b''
        
            # Recalculate offsets for all files
            for internal_path, file_info in self.file_table.items():
                # If this is a new file, use its data
                if new_file_data and internal_path == list(self.file_table.keys())[-1]:
                    file_data = new_file_data
                else:
                    # For existing files, extract data from current decrypted_data
                    if self.decrypted_data and file_info['offset'] + file_info['size'] <= len(self.decrypted_data):
                        file_data = self.decrypted_data[file_info['offset']:file_info['offset'] + file_info['size']]
                    else:
                        self.log.error(f"Cannot read file data for {internal_path}")
                        return False
            
                # Update offset and hash in table
                self.file_table[internal_path]['offset'] = current_offset
                self.file_table[internal_path]['hash'] = self._calculate_hash(file_data)
            
                all_file_data += file_data
                current_offset += len(file_data)
        
            # Save file table again with updated offsets
            file_table_data = self._save_file_table()
            file_table_size = len(file_table_data)
        
            # Recalculate file data start
            file_data_start = len(header) + 4 + file_table_size
            all_file_data = b''
        
            # Collect file data again in correct order
            for internal_path in self.file_table.keys():
                file_info = self.file_table[internal_path]
                if new_file_data and internal_path == list(self.file_table.keys())[-1]:
                    file_data = new_file_data
                else:
                    if self.decrypted_data and file_info['offset'] + file_info['size'] <= len(self.decrypted_data):
                        file_data = self.decrypted_data[file_info['offset']:file_info['offset'] + file_info['size']]
                    else:
                        self.log.error(f"Cannot read file data for {internal_path}")
                        return False
            
                all_file_data += file_data
        
            # Get current vault size
            current_size = self.metadata['size_bytes']
        
            # Calculate available space
            total_used = len(header) + 4 + file_table_size + len(all_file_data)
            available_space = current_size - total_used
        
            if available_space < 0:
                self.log.error("Vault is full")
                return False
        
            # Create structure: [header][file_table_size(4)][file_table_data][file_data]
            vault_data = (
                header +
                struct.pack('>I', file_table_size) +
                file_table_data +
                all_file_data +
                b'\x00' * available_space  # Fill with zeros
            )
        
            # Encrypt data
            if key:
                encrypted = encrypt_data(vault_data, key=key)
            else:
                encrypted = encrypt_data(vault_data, password=password)

            # Write back
            self.vault_path.write_bytes(encrypted)

            # Update decrypted_data
            self.decrypted_data = vault_data
            
            self.log.info(f"Vault rewritten successfully with {len(self.file_table)} files")
            return True
        
        except Exception as e:
            self.log.error(f"Failed to rewrite vault with data: {e}")
            return False
    
    def get_info(self, password: str = None, key: bytes = None) -> dict:
        """Return vault information with real data"""
        try:
            # Basic information
            info = {
                'path': str(self.vault_path),
                'status': 'ACTIVE' if self.vault_path.exists() else 'MISSING'
            }

            # File size on disk
            if self.vault_path.exists():
                disk_size = self.vault_path.stat().st_size
                info['disk_size_mb'] = disk_size // (1024 * 1024)

                # Get file creation date
                created_time = self.vault_path.stat().st_ctime
                info['created_at'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_time))
            else:
                info['disk_size_mb'] = 0
                info['created_at'] = 'Unknown'

            # IMPORTANT: Try to open vault for real data
            if self.vault_path.exists():
                # If vault already open, use current data
                if self.is_open and self.file_table:
                    total_size = self.metadata.get('size_bytes', 0)
                    file_count = len(self.file_table)
                    total_used = sum(f['size'] for f in self.file_table.values())
                    free_space = total_size - total_used

                    info['total_size_mb'] = total_size // (1024 * 1024)
                    info['file_count'] = file_count
                    info['used_space_mb'] = total_used // 1024 # KB
                    info['free_space_mb'] = free_space // (1024 * 1024)
                    info['files_list'] = list(self.file_table.keys())

                    # Use creation date from metadata if available
                    if 'created_at_str' in self.metadata:
                        info['created_at'] = self.metadata['created_at_str']

                    self.log.info(f"Vault info from opened state: {file_count} files, {total_used//1024}KB used")
                else:
                    # Try to open vault for information
                    try:
                        if self.open(password, key):
                            # Successfully opened - use real data
                            total_size = self.metadata.get('size_bytes', 0)
                            file_count = len(self.file_table)
                            total_used = sum(f['size'] for f in self.file_table.values())
                            free_space = total_size - total_used

                            info['total_size_mb'] = total_size // (1024 * 1024) # MB
                            info['file_count'] = file_count
                            info['used_space_mb'] = total_used // 1024 # KB
                            info['free_space_mb'] = free_space // (1024 * 1024) # MB
                            info['files_list'] = list(self.file_table.keys())

                            # Use creation date from metadata if available
                            if 'created_at_str' in self.metadata:
                                info['created_at'] = self.metadata['created_at_str']

                            self.log.info(f"Vault info after opening: {file_count} files, {total_used//1024}KB used")
                        else:
                            # Could not open - use basic information
                            self.log.warning(f"Could not open vault for detailed info: {self.vault_path}")
                            info['total_size_mb'] = info['disk_size_mb']
                            info['file_count'] = 0
                            info['used_space_mb'] = 0
                            info['free_space_mb'] = info['disk_size_mb']
                            info['files_list'] = []
                    except Exception as e:
                        self.log.error(f"Error opening vault for info: {e}")
                        info['total_size_mb'] = info['disk_size_mb']
                        info['file_count'] = 0
                        info['used_space_mb'] = 0
                        info['free_space_mb'] = info['disk_size_mb']
                        info['files_list'] = []
            else:
                # Vault does not exist
                info['total_size_mb'] = 0
                info['file_count'] = 0
                info['used_space_mb'] = 0
                info['free_space_mb'] = 0
                info['files_list'] = []

            self.log.info(f"Vault info: {info.get('file_count', 0)} files, {info.get('used_space_mb', 0)}KB used")
            return info

        except Exception as e:
            self.log.error(f"Error getting vault info: {e}")
            return {
                'path': str(self.vault_path),
                'status': 'ERROR',
                'created_at': 'Unknown',
                'file_count': 0,
                'disk_size_mb': 0,
                'total_size_mb': 0,
                'used_space_mb': 0,
                'free_space_mb': 0
            }

    def open(self, password: str = None, key: bytes = None) -> bool:
        """Open existing vault"""
        try:
            if not self.vault_path.exists():
                self.log.error(f"Vault file not found: {self.vault_path}")
                return False

            self.log.info(f"Opening vault: {self.vault_path}")
            encrypted_data = self.vault_path.read_bytes()

            # IMPORTANT: Check that at least one authentication method is provided
            if password is None and key is None:
                self.log.error("No authentication method provided (password or key)")
                return False

            try:
                if key:
                    self.log.debug("Using key for decryption")
                    decrypted = decrypt_data(encrypted_data, key=key)
                else:
                    self.log.debug("Using password for decryption")
                    decrypted = decrypt_data(encrypted_data, password=password)
            except Exception as e:
                self.log.error(f"Failed to decrypt vault: {e}")
                return False

            self.decrypted_data = decrypted

            success = self._read_header(decrypted)
            if success:
                self.log.info(f"Vault opened successfully: {self.vault_path}")
                # Load file table
                self.is_open = True
                return self._load_file_table(decrypted)
            else:
                self.log.error(f"Failed to open vault: invalid header or corrupted")
                return False

        except Exception as e:
            self.log.error(f"Error opening vault {self.vault_path}: {e}")
            return False