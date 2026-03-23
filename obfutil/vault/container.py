"""
Vault Container - Core encrypted container logic
Version 3.4 - Fixed rename with stored credentials
"""

import os
import json
import struct
import time
import hashlib
import hmac
import ctypes
import gc
import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from obfutil.crypto.encryption import encrypt_data, decrypt_data
from obfutil.utils.logger import get_logger
from obfutil.config import VAULTS_DIR


class VaultContainer:
    """
    Secure encrypted container for file storage with V3.4 enhancements
    """
    
    def __init__(self, vault_path: str):
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
        self._header_hmac_key = None
        
        # Store credentials for later operations (rename, remove, etc.)
        self._current_password = None
        self._current_key = None

    # ========== SECURITY METHODS ==========
    
    def secure_memory_cleanup(self):
        """Securely wipe sensitive data from memory"""
        try:
            self.log.info("Performing secure memory cleanup")
            
            if self.decrypted_data:
                if isinstance(self.decrypted_data, (bytes, bytearray)):
                    buffer = bytearray(self.decrypted_data)
                    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, len(buffer))
                self.decrypted_data = None
            
            for file_info in self.file_table.values():
                if 'hash' in file_info:
                    file_info['hash'] = '0' * 64
            
            if self._header_hmac_key:
                if isinstance(self._header_hmac_key, (bytes, bytearray)):
                    buffer = bytearray(self._header_hmac_key)
                    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, len(buffer))
                self._header_hmac_key = None
            
            # Clear stored credentials
            self._current_password = None
            self._current_key = None
            
            gc.collect()
            
        except Exception as e:
            self.log.error(f"Secure memory cleanup error: {e}")
    
    def secure_close(self):
        """Safely close vault with guaranteed memory cleanup"""
        self.secure_memory_cleanup()
        self.is_open = False
        self.log.info("Vault securely closed")

    # ========== VAULT OPEN/CLOSE ==========
    
    def open(self, password: str = None, key: bytes = None, quick_mode: bool = False) -> bool:
        """Open existing vault and store credentials for later use"""
        try:
            current_time = time.time()
            if self.failed_attempts >= 3:
                time_since_last_attempt = current_time - self.last_attempt_time
                if time_since_last_attempt < (2 ** self.failed_attempts):
                    wait_time = (2 ** self.failed_attempts) - time_since_last_attempt
                    self.log.warning(f"Too many failed attempts. Waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)
            
            if not self.vault_path.exists():
                self.log.error(f"Vault file not found: {self.vault_path}")
                return False
                
            self.log.info(f"Opening vault: {self.vault_path}")
            encrypted_data = self.vault_path.read_bytes()
            
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
                self.failed_attempts = 0
                
                # Store credentials for later operations
                self._current_password = password
                self._current_key = key
                
                if quick_mode:
                    return self._load_file_table_metadata_only(decrypted)
                else:
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

    def create(self, size_mb: int, password: str = None, key: bytes = None):
        """Create new vault container"""
        try:
            self.log.info(f"Creating vault container: {self.vault_path} ({size_mb}MB)")
            
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            
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
            
            self.file_table = {}
            header = self._create_header()
            file_table_data = self._save_file_table()
            
            header_size = len(header)
            file_table_size = len(file_table_data) + 4
            available_space = size_mb * 1024 * 1024 - header_size - file_table_size
            
            if available_space < 0:
                self.log.error("Vault size too small")
                return False
                
            empty_data = b'\x00' * available_space
            
            vault_data = (
                header +
                struct.pack('>I', len(file_table_data)) +
                file_table_data +
                empty_data
            )
            
            self.log.info(f"Encrypting vault data ({len(vault_data)} bytes)")
            
            if key:
                encrypted = encrypt_data(vault_data, key=key)
            else:
                encrypted = encrypt_data(vault_data, password=password)
                
            self.vault_path.write_bytes(encrypted)
            
            # Store credentials
            self._current_password = password
            self._current_key = key
            self.is_open = True
            self.decrypted_data = vault_data
            
            self.log.info(f"Vault container created successfully: {self.vault_path}")
            return True
            
        except Exception as e:
            self.log.error(f"Failed to create vault container: {e}")
            return False

    # ========== FILE OPERATIONS ==========
    
    def add_file(self, file_path: Path, internal_path: str, password: str = None, 
                 key: bytes = None, force: bool = False) -> bool:
        """Add file to vault with space check and force option"""
        try:
            if not file_path.exists():
                self.log.error(f"Source file not found: {file_path}")
                return False
            
            file_data = file_path.read_bytes()
            file_size = len(file_data)
            
            # Check if file already exists
            if internal_path in self.file_table:
                if not force:
                    self.log.error(f"File already exists: {internal_path}")
                    return False
                else:
                    self.log.warning(f"Overwriting existing file: {internal_path}")
            
            # Check available space
            has_space, free_space = self.check_space_available(file_size, internal_path if force else None)
            if not has_space:
                self.log.error(f"Not enough space: need {file_size} bytes, free {free_space} bytes")
                return False
            
            self.log.info(f"Adding file to vault: {internal_path} ({file_size} bytes)")
            
            # Add to file table
            self.file_table[internal_path] = {
                'size': file_size,
                'added_at': time.time(),
                'original_name': file_path.name,
                'internal_path': internal_path,
                'offset': 0,
                'hash': hashlib.sha256(file_data).hexdigest()
            }
            
            self.metadata['file_count'] = len(self.file_table)
            
            # Use stored credentials if available, otherwise use provided
            pwd = password or self._current_password
            k = key or self._current_key
            
            success = self._rewrite_vault_with_data(file_data, pwd, k)
            
            if success:
                self.log.info(f"File {internal_path} added successfully")
            else:
                del self.file_table[internal_path]
                self.metadata['file_count'] = len(self.file_table)
                self.log.error(f"Failed to add file, rolled back")
                
            return success
            
        except Exception as e:
            self.log.error(f"Failed to add file to vault: {e}")
            return False
    
    def extract_file(self, internal_path: str, output_path: Path, 
                 password: str = None, key: bytes = None,
                 show_progress: bool = True) -> bool:
        """Extract file from vault with hash verification"""
        try:
            self.log.info(f"Starting file extraction: {internal_path}")
        
            if internal_path not in self.file_table:
                self.log.error(f"File '{internal_path}' not found in file table")
                return False

            file_info = self.file_table[internal_path]
        
            if not self.is_open or not self.decrypted_data:
                self.log.info("Vault not open, opening for extraction")
                if not self.open(password, key):
                    self.log.error("Failed to open vault for extraction")
                    return False
        
            if file_info.get('offset', 0) + file_info.get('size', 0) > len(self.decrypted_data):
                self.log.error(f"File data out of bounds")
                return False
            
            start = file_info.get('offset', 0)
            end = start + file_info.get('size', 0)
            file_data = self.decrypted_data[start:end]
        
            # Verify hash
            expected_hash = file_info.get('hash')
            if expected_hash and expected_hash != '0' * 64:
                file_hash = hashlib.sha256(file_data).hexdigest()
                self.log.debug(f"Hash check - Expected: {expected_hash[:16]}..., Actual: {file_hash[:16]}...")
                if file_hash != expected_hash:
                    self.log.error(f"File integrity check failed for {internal_path}")
                    self.log.error(f"  Expected hash: {expected_hash}")
                    self.log.error(f"  Actual hash:   {file_hash}")
                    return False
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(file_data)
            self.log.info(f"File successfully written to: {output_path}")
        
            return True
        
        except Exception as e:
            self.log.error(f"Failed to extract file from vault: {str(e)}")
            return False
    
    def remove_file(self, internal_path: str, password: str = None, key: bytes = None) -> bool:
        """Remove file from vault"""
        try:
            if internal_path not in self.file_table:
                self.log.error(f"File not found in vault: {internal_path}")
                return False

            file_info = self.file_table[internal_path]
            self.log.info(f"Removing file from vault: {internal_path} ({file_info.get('size', 0)} bytes)")
            
            del self.file_table[internal_path]
            self.metadata['file_count'] = len(self.file_table)
            
            # Use stored credentials
            pwd = password or self._current_password
            k = key or self._current_key
            
            success = self._rewrite_vault_with_data(None, pwd, k)
            if success:
                self.log.info(f"File {internal_path} removed successfully")
            return success
            
        except Exception as e:
            self.log.error(f"Failed to remove file from vault: {e}")
            return False
    
    def rename_file(self, old_path: str, new_path: str, password: str = None, key: bytes = None) -> bool:
        """
        Rename a file inside the vault
        
        Args:
            old_path: Current internal path
            new_path: New internal path
            password: Password (optional, uses stored if not provided)
            key: Key file (optional, uses stored if not provided)
        """
        if not self.is_open:
            self.log.error("Vault not open, cannot rename")
            return False
            
        if old_path not in self.file_table:
            self.log.error(f"File not found: {old_path}")
            return False
            
        if new_path in self.file_table:
            self.log.error(f"Target path already exists: {new_path}")
            return False
        
        self.log.info(f"Renaming file: {old_path} -> {new_path}")
        
        # Get file data before renaming (to keep hash consistent)
        file_info = self.file_table[old_path]
        file_data = None
        
        if self.decrypted_data and file_info.get('offset', 0) + file_info.get('size', 0) <= len(self.decrypted_data):
            start = file_info.get('offset', 0)
            end = start + file_info.get('size', 0)
            file_data = self.decrypted_data[start:end]
        
        # Rename by moving entry in file_table
        self.file_table[new_path] = self.file_table.pop(old_path)
        self.file_table[new_path]['internal_path'] = new_path
        
        # Update hash to ensure it matches the actual data
        if file_data:
            new_hash = hashlib.sha256(file_data).hexdigest()
            self.file_table[new_path]['hash'] = new_hash
            self.log.debug(f"Updated hash for {new_path}: {new_hash[:16]}...")
        
        # Use stored credentials
        pwd = password or self._current_password
        k = key or self._current_key
        
        # Need to rewrite vault to save changes
        try:
            success = self._rewrite_vault_with_data(None, pwd, k)
            
            if success:
                self.log.info(f"File renamed: {old_path} -> {new_path}")
                return True
            else:
                # Rollback on failure
                self.file_table[old_path] = self.file_table.pop(new_path)
                self.log.error(f"Failed to rename file, rolled back")
                return False
                
        except Exception as e:
            self.log.error(f"Error during rename: {e}")
            # Rollback
            if new_path in self.file_table:
                self.file_table[old_path] = self.file_table.pop(new_path)
            return False

    # ========== SEARCH AND STATISTICS ==========
    
    def search_files(self, pattern: str, search_type: str = 'name') -> List[str]:
        """Search for files by pattern"""
        results = []
        
        for path in self.file_table.keys():
            if search_type == 'name':
                if fnmatch.fnmatch(path, pattern):
                    results.append(path)
            elif search_type == 'ext':
                ext = path.split('.')[-1].lower() if '.' in path else ''
                if pattern.lower() == ext:
                    results.append(path)
            elif search_type == 'contains':
                if pattern.lower() in path.lower():
                    results.append(path)
                    
        self.log.info(f"Search '{pattern}' found {len(results)} files")
        return results
    
    def get_folder_usage(self) -> Dict[str, int]:
        """Calculate storage usage by folder"""
        usage = {}
        
        for path, info in self.file_table.items():
            folder = str(Path(path).parent)
            if folder == '.':
                folder = '/'
            usage[folder] = usage.get(folder, 0) + info.get('size', 0)
            
        return usage
    
    def get_vault_statistics(self) -> Dict:
        """Generate comprehensive statistics about vault contents"""
        if not self.is_open:
            self.log.warning("Vault not open, cannot get statistics")
            return {}
        
        files = self.file_table
        if not files:
            return {
                'total_files': 0,
                'total_size_bytes': 0,
                'total_size_mb': 0,
                'avg_size_kb': 0,
                'largest_file': None,
                'oldest_file': None,
                'newest_file': None,
                'file_types': {},
                'type_sizes': {}
            }
        
        total_files = len(files)
        total_size = sum(info.get('size', 0) for info in files.values())
        avg_size = total_size / total_files if total_files > 0 else 0
        
        largest = max(files.items(), key=lambda x: x[1].get('size', 0)) if files else None
        oldest = min(files.items(), key=lambda x: x[1].get('added_at', float('inf'))) if files else None
        newest = max(files.items(), key=lambda x: x[1].get('added_at', 0)) if files else None
        
        from collections import defaultdict
        file_types = defaultdict(int)
        type_sizes = defaultdict(int)
        
        for path, info in files.items():
            ext = path.split('.')[-1].lower() if '.' in path else 'no_extension'
            file_types[ext] += 1
            type_sizes[ext] += info.get('size', 0)
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'avg_size_kb': round(avg_size / 1024, 2),
            'largest_file': {
                'name': largest[0],
                'size_bytes': largest[1].get('size', 0),
                'size_mb': round(largest[1].get('size', 0) / (1024 * 1024), 2)
            } if largest else None,
            'oldest_file': {
                'name': oldest[0],
                'added_at': time.strftime('%Y-%m-%d %H:%M:%S', 
                                         time.localtime(oldest[1].get('added_at', 0)))
            } if oldest else None,
            'newest_file': {
                'name': newest[0],
                'added_at': time.strftime('%Y-%m-%d %H:%M:%S', 
                                         time.localtime(newest[1].get('added_at', 0)))
            } if newest else None,
            'file_types': dict(file_types),
            'type_sizes': {ext: round(size / (1024 * 1024), 2) for ext, size in type_sizes.items()}
        }
    
    def check_space_available(self, size_bytes: int, old_path: str = None) -> Tuple[bool, int]:
        """Check if there's enough free space in vault"""
        if not self.is_open:
            return False, 0
            
        used_space = sum(info.get('size', 0) for info in self.file_table.values())
        
        if old_path and old_path in self.file_table:
            used_space -= self.file_table[old_path].get('size', 0)
        
        total_space = self.metadata.get('size_bytes', 0)
        free_space = total_space - used_space
        required_space = size_bytes + 1024
        
        return free_space >= required_space, free_space

    # ========== INTERNAL METHODS ==========
    
    def list_files(self) -> List[str]:
        return list(self.file_table.keys())
    
    def quick_preview(self, password: str = None, key: bytes = None) -> Dict:
        """Get vault metadata and file list without loading file data"""
        try:
            if not self.is_open:
                if not self.open(password, key, quick_mode=True):
                    return {'status': 'error', 'message': 'Failed to open vault'}
            
            preview = {
                'status': 'success',
                'vault_name': self.vault_path.name,
                'file_count': len(self.file_table),
                'total_size_bytes': sum(f.get('size', 0) for f in self.file_table.values()),
                'total_size_mb': sum(f.get('size', 0) for f in self.file_table.values()) // (1024 * 1024),
                'created_at': self.metadata.get('created_at_str', 'Unknown'),
                'version': self.metadata.get('version', '1.0'),
                'files': []
            }
            
            for internal_path, file_info in self.file_table.items():
                preview['files'].append({
                    'name': internal_path,
                    'size_bytes': file_info.get('size', 0),
                    'size_kb': file_info.get('size', 0) // 1024,
                    'added_date': time.strftime('%Y-%m-%d', time.localtime(file_info.get('added_at', 0))),
                    'original_name': file_info.get('original_name', '')
                })
            
            return preview
            
        except Exception as e:
            self.log.error(f"Quick preview error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def deep_integrity_check(self, password: str = None, key: bytes = None) -> Dict:
        """Comprehensive vault integrity verification"""
        try:
            self.log.info("Starting deep integrity check")
            
            if not self.is_open:
                if not self.open(password, key):
                    return {'status': 'error', 'message': 'Cannot open vault'}
            
            results = {
                'status': 'success',
                'checks_passed': 0,
                'checks_total': 2,
                'overall_status': 'healthy',
                'issues': [],
                'files_checked': len(self.file_table)
            }
            
            if self._verify_header_integrity():
                results['checks_passed'] += 1
            else:
                results['issues'].append("Header integrity check failed")
            
            if self._verify_file_table_consistency():
                results['checks_passed'] += 1
            else:
                results['issues'].append("File table consistency check failed")
            
            if results['checks_passed'] == results['checks_total']:
                results['overall_status'] = 'healthy'
            elif results['checks_passed'] >= results['checks_total'] * 0.7:
                results['overall_status'] = 'degraded'
            else:
                results['overall_status'] = 'corrupted'
            
            return results
            
        except Exception as e:
            self.log.error(f"Deep integrity check error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def debug_file_info(self, internal_path: str):
        """Debug method to check file information"""
        if internal_path in self.file_table:
            file_info = self.file_table[internal_path]
            self.log.info(f"File debug info for {internal_path}:")
            self.log.info(f"  - Size: {file_info.get('size', 0)}")
            self.log.info(f"  - Offset: {file_info.get('offset', 0)}")
            self.log.info(f"  - Hash: {file_info.get('hash', 'MISSING')}")
            
            if self.decrypted_data:
                end_offset = file_info.get('offset', 0) + file_info.get('size', 0)
                self.log.info(f"  - Data bounds: {file_info.get('offset', 0)} to {end_offset} (total: {len(self.decrypted_data)})")
                
                if end_offset <= len(self.decrypted_data):
                    start = file_info.get('offset', 0)
                    end = start + file_info.get('size', 0)
                    file_data = self.decrypted_data[start:end]
                    self.log.info(f"  - Actual data size: {len(file_data)}")

    # ========== HEADER AND FILE TABLE METHODS ==========
    
    def _verify_header_integrity(self) -> bool:
        required_fields = ['version', 'size_bytes', 'created_at', 'file_count']
        return all(field in self.metadata for field in required_fields)
    
    def _verify_file_table_consistency(self) -> bool:
        for path, info in self.file_table.items():
            required = ['size', 'offset', 'hash', 'added_at']
            if not all(field in info for field in required):
                return False
            if info.get('size', 0) < 0 or info.get('offset', 0) < 0:
                return False
        return True
    
    def _load_file_table_metadata_only(self, decrypted_data: bytes) -> bool:
        """Load only file table metadata"""
        try:
            metadata_len = struct.unpack('>I', decrypted_data[:4])[0]
            header_size = 4 + metadata_len
            
            file_table_size = struct.unpack('>I', decrypted_data[header_size:header_size+4])[0]
            file_table_start = header_size + 4
            file_table_end = file_table_start + file_table_size
            file_table_json = decrypted_data[file_table_start:file_table_end]
            
            self.file_data_offset = file_table_end
            
            if file_table_json:
                file_table_data = json.loads(file_table_json.decode('utf-8'))
                self.file_table = file_table_data.get('files', {})
                self.log.info(f"Loaded file table with {len(self.file_table)} files (metadata only)")
                return True
            else:
                self.file_table = {}
                return True
                
        except Exception as e:
            self.log.error(f"Failed to load file table metadata: {e}")
            self.file_table = {}
            return False
    
    def _load_file_table(self, decrypted_data: bytes) -> bool:
        """Load full file table"""
        try:
            metadata_len = struct.unpack('>I', decrypted_data[:4])[0]
            header_size = 4 + metadata_len
            
            file_table_size = struct.unpack('>I', decrypted_data[header_size:header_size+4])[0]
            file_table_start = header_size + 4
            file_table_end = file_table_start + file_table_size
            file_table_json = decrypted_data[file_table_start:file_table_end]
            
            self.file_data_offset = file_table_end
            
            if file_table_json:
                file_table_data = json.loads(file_table_json.decode('utf-8'))
                self.file_table = file_table_data.get('files', {})
                self.log.info(f"Loaded file table with {len(self.file_table)} files")
                return True
            else:
                self.file_table = {}
                return True
                
        except Exception as e:
            self.log.error(f"Failed to load file table: {e}")
            self.file_table = {}
            return False
    
    def _save_file_table(self) -> bytes:
        """Save file table to bytes"""
        try:
            file_table_data = {
                'files': self.file_table,
                'timestamp': time.time(),
                'file_count': len(self.file_table)
            }
            return json.dumps(file_table_data, indent=2, ensure_ascii=False).encode('utf-8')
        except Exception as e:
            self.log.error(f"Failed to save file table: {e}")
            return b'{}'
    
    def _create_header(self) -> bytes:
        """Create vault header"""
        try:
            metadata_json = json.dumps(self.metadata, ensure_ascii=False).encode('utf-8')
            return struct.pack('>I', len(metadata_json)) + metadata_json
        except Exception as e:
            self.log.error(f"Failed to create vault header: {e}")
            empty_json = json.dumps({}).encode('utf-8')
            return struct.pack('>I', len(empty_json)) + empty_json
    
    def _read_header(self, data: bytes) -> bool:
        """Read vault header"""
        try:
            metadata_len = struct.unpack('>I', data[:4])[0]
            metadata_json = data[4:4 + metadata_len]
            self.metadata = json.loads(metadata_json.decode('utf-8'))
            return True
        except Exception as e:
            self.log.error(f"Failed to read vault header: {e}")
            return False
    
    def _rewrite_vault_with_data(self, new_file_data: bytes = None, 
                                  password: str = None, key: bytes = None) -> bool:
        """Rewrite vault with data"""
        try:
            # Ensure we have valid structures
            if not hasattr(self, 'file_table'):
                self.file_table = {}
            if not hasattr(self, 'metadata'):
                self.metadata = {'size_bytes': 10 * 1024 * 1024, 'file_count': 0}
            
            # Check if we have credentials
            if password is None and key is None:
                self.log.error("No password or key provided for rewrite")
                return False
            
            header = self._create_header()
            file_table_data = self._save_file_table()
            file_table_size = len(file_table_data)
            
            # Collect all file data
            all_file_data = b''
            current_offset = len(header) + 4 + file_table_size
            
            for internal_path, file_info in self.file_table.items():
                if new_file_data and internal_path == list(self.file_table.keys())[-1]:
                    file_data = new_file_data
                else:
                    if self.decrypted_data and file_info.get('offset', 0) + file_info.get('size', 0) <= len(self.decrypted_data):
                        start = file_info.get('offset', 0)
                        end = start + file_info.get('size', 0)
                        file_data = self.decrypted_data[start:end]
                    else:
                        self.log.error(f"Cannot read file data for {internal_path}")
                        return False
                
                self.file_table[internal_path]['offset'] = current_offset
                all_file_data += file_data
                current_offset += len(file_data)
            
            # Update file table with new offsets
            file_table_data = self._save_file_table()
            file_table_size = len(file_table_data)
            
            # Build final vault data
            vault_data = (
                header +
                struct.pack('>I', file_table_size) +
                file_table_data +
                all_file_data
            )
            
            # Pad to required size
            current_size = self.metadata.get('size_bytes', 10 * 1024 * 1024)
            current_len = len(vault_data)
            if current_len < current_size:
                vault_data += b'\x00' * (current_size - current_len)
            elif current_len > current_size:
                self.log.error(f"Vault size exceeded: {current_len} > {current_size}")
                return False
            
            # Encrypt
            try:
                if key:
                    encrypted = encrypt_data(vault_data, key=key)
                else:
                    encrypted = encrypt_data(vault_data, password=password)
            except Exception as e:
                self.log.error(f"Encryption failed: {e}")
                return False
            
            # Save
            self.vault_path.write_bytes(encrypted)
            self.decrypted_data = vault_data
            
            self.log.info(f"Vault rewritten successfully with {len(self.file_table)} files")
            return True
            
        except Exception as e:
            self.log.error(f"Failed to rewrite vault with data: {e}")
            import traceback
            self.log.error(traceback.format_exc())
            return False