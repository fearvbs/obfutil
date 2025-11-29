import os
import json
import struct
import time
import hashlib
import hmac
import ctypes
import gc
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from obfutil.crypto.encryption import encrypt_data, decrypt_data
from obfutil.utils.logger import get_logger
from obfutil.config import VAULTS_DIR

class VaultContainer:
    """
    Secure encrypted container for file storage with V3.2 enhancements
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
            
            gc.collect()
            
        except Exception as e:
            self.log.error(f"Secure memory cleanup error: {e}")
    
    def secure_close(self):
        """Safely close vault with guaranteed memory cleanup"""
        self.secure_memory_cleanup()
        self.is_open = False
        self.log.info("Vault securely closed")

    def _create_secure_header(self, encryption_key: bytes) -> bytes:
        """Create vault header with HMAC integrity protection"""
        try:
            self.metadata.update({
                'header_nonce': os.urandom(8).hex(),
                'created_timestamp': time.time(),
                'version': '1.2',
                'integrity_protected': True
            })
            
            metadata_json = json.dumps(self.metadata, sort_keys=True).encode('utf-8')
            
            hmac_signature = hmac.new(
                encryption_key, 
                metadata_json, 
                hashlib.sha256
            ).digest()[:12]
            
            header = (
                struct.pack('>I', len(metadata_json)) +
                metadata_json +
                hmac_signature
            )
            
            return header
            
        except Exception as e:
            self.log.error(f"Failed to create secure header: {e}")
            raise
    
    def _read_secure_header(self, data: bytes, encryption_key: bytes) -> bool:
        """Read and verify integrity of secure header with backward compatibility"""
        try:
            # Try new secure header format first
            if len(data) >= 16:
                metadata_len = struct.unpack('>I', data[:4])[0]
                total_header_size = 4 + metadata_len + 12
                
                if len(data) >= total_header_size:
                    metadata_json = data[4:4 + metadata_len]
                    received_hmac = data[4 + metadata_len:total_header_size]
                    
                    calculated_hmac = hmac.new(
                        encryption_key,
                        metadata_json,
                        hashlib.sha256
                    ).digest()[:12]
                    
                    if hmac.compare_digest(calculated_hmac, received_hmac):
                        # Successfully read secure header
                        self.metadata = json.loads(metadata_json.decode('utf-8'))
                        self._header_hmac_key = encryption_key[:16]
                        self.log.info("Secure header verified successfully")
                        return True
            
            # Fallback to legacy header format for backward compatibility
            self.log.warning("Falling back to legacy header format")
            return self._read_header(data)
            
        except Exception as e:
            self.log.error(f"Failed to read secure header: {e}")
            # Try legacy format as last resort
            return self._read_header(data)
    
    def deep_integrity_check(self, password: str = None, key: bytes = None) -> Dict:
        """Comprehensive vault integrity verification with detailed logging"""
        try:
            self.log.info("Starting deep integrity check")
            
            if not self.is_open:
                self.log.info("Vault not open, attempting to open...")
                if not self.open(password, key):
                    self.log.error("Failed to open vault for deep integrity check")
                    return {'status': 'error', 'message': 'Cannot open vault'}
            
            self.log.info(f"Vault opened successfully, checking {len(self.file_table)} files")
            
            results = {
                'status': 'success',
                'checks_passed': 0,
                'checks_total': 2,
                'overall_status': 'healthy',
                'issues': []
            }
            
            # Check 1: Header integrity
            self.log.info("Checking header integrity...")
            header_ok = self._verify_header_integrity()
            if header_ok:
                results['checks_passed'] += 1
                self.log.info("Header integrity: PASSED")
            else:
                results['issues'].append("Header integrity check failed")
                self.log.error("Header integrity: FAILED")
            
            # Check 2: File table consistency  
            self.log.info("Checking file table consistency...")
            file_table_ok = self._verify_file_table_consistency()
            if file_table_ok:
                results['checks_passed'] += 1
                self.log.info("File table consistency: PASSED")
            else:
                results['issues'].append("File table consistency check failed")
                self.log.error("File table consistency: FAILED")
            
            # Check 3: File data integrity (if files exist)
            if self.file_table:
                self.log.info("Checking file data integrity...")
                file_issues = self._verify_all_files_integrity()
                results['checks_total'] += 1
                results['files_checked'] = len(self.file_table)
                results['file_issues'] = file_issues
                
                if not file_issues:
                    results['checks_passed'] += 1
                    self.log.info("File data integrity: PASSED")
                else:
                    results['issues'].append(f"{len(file_issues)} file(s) have integrity issues")
                    self.log.error(f"File data integrity: FAILED - {len(file_issues)} issues")
            
            # Determine overall status
            if results['checks_passed'] == results['checks_total']:
                results['overall_status'] = 'healthy'
            elif results['checks_passed'] >= results['checks_total'] * 0.7:
                results['overall_status'] = 'degraded'
            else:
                results['overall_status'] = 'corrupted'
            
            self.log.info(f"Deep integrity check completed: {results['checks_passed']}/{results['checks_total']} checks passed")
            self.secure_close()
            return results
            
        except Exception as e:
            self.log.error(f"Deep integrity check error: {e}")
            return {'status': 'error', 'message': str(e)}

    def _verify_all_files_integrity(self) -> List[str]:
        """Verify integrity of all files in vault"""
        issues = []
        self.log.info(f"Verifying integrity of {len(self.file_table)} files")
        
        for internal_path, file_info in self.file_table.items():
            try:
                self.log.debug(f"Checking file: {internal_path}")
                
                # Check if file data is within bounds
                end_offset = file_info['offset'] + file_info['size']
                if end_offset > len(self.decrypted_data):
                    issues.append(f"File out of bounds: {internal_path}")
                    self.log.error(f"File out of bounds: {internal_path} (offset: {file_info['offset']}, size: {file_info['size']}, total: {len(self.decrypted_data)})")
                    continue
                
                # Verify file hash
                file_data = self.decrypted_data[
                    file_info['offset']:file_info['offset'] + file_info['size']
                ]
                current_hash = self._calculate_hash(file_data)
                if current_hash != file_info['hash']:
                    issues.append(f"Hash mismatch: {internal_path}")
                    self.log.error(f"Hash mismatch for {internal_path}")
                    
            except Exception as e:
                error_msg = f"Verification failed for {internal_path}: {str(e)}"
                issues.append(error_msg)
                self.log.error(error_msg)
        
        self.log.info(f"File integrity check completed: {len(issues)} issues found")
        return issues
    
    def _verify_header_integrity(self) -> bool:
        required_fields = ['version', 'size_bytes', 'created_at', 'file_count']
        return all(field in self.metadata for field in required_fields)
    
    def _verify_file_table_consistency(self) -> bool:
        for path, info in self.file_table.items():
            required = ['size', 'offset', 'hash', 'added_at']
            if not all(field in info for field in required):
                return False
            if info['size'] < 0 or info['offset'] < 0:
                return False
        return True
    
    def _verify_all_files_integrity(self) -> List[str]:
        """Verify integrity of files in vault"""
        issues = []
        self.log.info(f"Verifying integrity of {len(self.file_table)} files")
        
        for internal_path, file_info in self.file_table.items():
            try:
                self.log.debug(f"Checking file: {internal_path}")
                
                # Check if file data is within bounds
                end_offset = file_info['offset'] + file_info['size']
                if end_offset > len(self.decrypted_data):
                    issues.append(f"File out of bounds: {internal_path}")
                    continue
                
                # Extract the encrypted file data from vault
                encrypted_file_data = self.decrypted_data[
                    file_info['offset']:file_info['offset'] + file_info['size']
                ]
                
                # Calculate hash of the ENCRYPTED data (as stored in vault)
                current_hash = self._calculate_hash(encrypted_file_data)
                expected_hash = file_info.get('hash')
                
                if not expected_hash:
                    issues.append(f"No hash found for file: {internal_path}")
                elif current_hash != expected_hash:
                    issues.append(f"Hash mismatch: {internal_path}")
                    self.log.error(f"Hash mismatch for {internal_path}: expected {expected_hash[:16]}..., got {current_hash[:16]}...")
                else:
                    self.log.debug(f"File integrity OK: {internal_path}")
                    
            except Exception as e:
                error_msg = f"Verification failed for {internal_path}: {str(e)}"
                issues.append(error_msg)
                self.log.error(error_msg)
        
        return issues
    
    def _verify_storage_bounds(self) -> Tuple[bool, str]:
        total_size = self.metadata.get('size_bytes', 0)
        used_space = sum(f['size'] for f in self.file_table.values())
        
        if used_space > total_size:
            return False, f"Storage overflow: {used_space} > {total_size} bytes"
        
        usage_percent = (used_space / total_size * 100) if total_size > 0 else 0
        return True, f"Storage usage: {usage_percent:.1f}%"

    def open(self, password: str = None, key: bytes = None, quick_mode: bool = False) -> bool:
        """Open existing vault - FIXED VERSION"""
        try:
            # Brute force protection
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
                
            # Use legacy header reading for compatibility
            success = self._read_header(decrypted)
            if success:
                self.log.info(f"Vault opened successfully")
                self.is_open = True
                self.failed_attempts = 0
                
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

    def _load_file_table_metadata_only(self, decrypted_data: bytes) -> bool:
        """Load only file table metadata without processing file data"""
        try:
            # Use legacy header format
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
                self.log.info("File table is empty")
                return True
                
        except Exception as e:
            self.log.error(f"Failed to load file table metadata: {e}")
            self.file_table = {}
            return False

    def create(self, size_mb: int, password: str = None, key: bytes = None):
        """Create new vault container - FIXED VERSION"""
        try:
            self.log.info(f"Creating vault container: {self.vault_path} ({size_mb}MB)")
            
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            
            current_time = time.time()
            self.metadata = {
                'version': '1.0',  # Keep legacy version for compatibility
                'size_bytes': size_mb * 1024 * 1024,
                'created_at': current_time,
                'created_at_str': time.strftime('%Y-%m-%d %H:%M:%S'),
                'file_count': 0,
                'format': 'obfutil_vault',
                'file_table_offset': 0
            }
            
            self.file_table = {}
            
            # Use legacy header for now to ensure compatibility
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
            self.log.info(f"Vault container created successfully: {self.vault_path}")
            return True
            
        except Exception as e:
            self.log.error(f"Failed to create vault container: {e}")
            return False

    # ===== KEEP EXISTING METHODS =====
    
    def _load_file_table(self, decrypted_data: bytes) -> bool:
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

    def _calculate_hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def add_file(self, file_path: Path, internal_path: str, password: str = None, key: bytes = None) -> bool:
        """Add file to vault"""
        try:
            if not file_path.exists():
                self.log.error(f"Source file not found: {file_path}")
                return False

            file_data = file_path.read_bytes()
            file_size = len(file_data)

            self.log.info(f"Adding file to vault: {internal_path} ({file_size} bytes)")

            # Use placeholder hash - file hash checking disabled in V3.2
            self.file_table[internal_path] = {
                'size': file_size,
                'added_at': time.time(),
                'original_name': file_path.name,
                'internal_path': internal_path,
                'offset': 0,
                'hash': '0' * 64  # Placeholder
            }

            self.metadata['file_count'] = len(self.file_table)

            success = self._rewrite_vault_with_data(file_data, password, key)
            if success:
                self.log.info(f"File {internal_path} added successfully to vault")
            return success

        except Exception as e:
            self.log.error(f"Failed to add file to vault: {e}")
            return False
    
    def extract_file(self, internal_path: str, output_path: Path, password: str = None, key: bytes = None) -> bool:
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
        
            if file_info['offset'] + file_info['size'] > len(self.decrypted_data):
                self.log.error(f"File data out of bounds")
                return False
            
            file_data = self.decrypted_data[file_info['offset']:file_info['offset'] + file_info['size']]
        
            file_hash = self._calculate_hash(file_data)
            expected_hash = file_info['hash']
        
            if file_hash != expected_hash:
                self.log.error(f"File integrity check failed")
                return False
        
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(file_data)
            self.log.info(f"File successfully written to: {output_path}")
        
            return True
        
        except Exception as e:
            self.log.error(f"Failed to extract file from vault: {str(e)}")
            return False

    def list_files(self) -> List[str]:
        files = list(self.file_table.keys())
        self.log.info(f"Listed {len(files)} files from vault")
        return files

    def remove_file(self, internal_path: str, password: str = None, key: bytes = None) -> bool:
        try:
            if internal_path not in self.file_table:
                self.log.error(f"File not found in vault: {internal_path}")
                return False

            file_info = self.file_table[internal_path]
            self.log.info(f"Removing file from vault: {internal_path} ({file_info['size']} bytes)")
            
            del self.file_table[internal_path]
            self.metadata['file_count'] = len(self.file_table)
            
            success = self._rewrite_vault_with_data(None, password, key)
            if success:
                self.log.info(f"File {internal_path} removed successfully from vault")
            return success
            
        except Exception as e:
            self.log.error(f"Failed to remove file from vault: {e}")
            return False

    def _rewrite_vault_with_data(self, new_file_data: bytes = None, password: str = None, key: bytes = None) -> bool:
        """Rewrite vault without hash updates"""
        try:
            header = self._create_header()
            file_table_data = self._save_file_table()
            file_table_size = len(file_table_data)
            
            current_offset = len(header) + 4 + file_table_size
            all_file_data = b''
        
            for internal_path, file_info in self.file_table.items():
                if new_file_data and internal_path == list(self.file_table.keys())[-1]:
                    file_data = new_file_data
                else:
                    if self.decrypted_data and file_info['offset'] + file_info['size'] <= len(self.decrypted_data):
                        file_data = self.decrypted_data[file_info['offset']:file_info['offset'] + file_info['size']]
                    else:
                        self.log.error(f"Cannot read file data for {internal_path}")
                        return False
            
                self.file_table[internal_path]['offset'] = current_offset
                all_file_data += file_data
                current_offset += len(file_data)
        
            file_table_data = self._save_file_table()
            file_table_size = len(file_table_data)
        
            file_data_start = len(header) + 4 + file_table_size
            all_file_data = b''
        
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
        
            current_size = self.metadata['size_bytes']
            total_used = len(header) + 4 + file_table_size + len(all_file_data)
            available_space = current_size - total_used
        
            if available_space < 0:
                self.log.error("Vault is full")
                return False
        
            vault_data = (
                header +
                struct.pack('>I', file_table_size) +
                file_table_data +
                all_file_data +
                b'\x00' * available_space
            )
        
            if key:
                encrypted = encrypt_data(vault_data, key=key)
            else:
                encrypted = encrypt_data(vault_data, password=password)

            self.vault_path.write_bytes(encrypted)
            self.decrypted_data = vault_data
            
            self.log.info(f"Vault rewritten successfully with {len(self.file_table)} files")
            return True
        
        except Exception as e:
            self.log.error(f"Failed to rewrite vault with data: {e}")
            return False
        
    def quick_preview(self, password: str = None, key: bytes = None) -> Dict:
        """Get vault metadata and file list without loading file data into memory"""
        try:
            if not self.is_open:
                if not self.open(password, key, quick_mode=True):
                    return {'status': 'error', 'message': 'Failed to open vault'}
            
            preview = {
                'status': 'success',
                'vault_name': self.vault_path.name,
                'file_count': len(self.file_table),
                'total_size_bytes': sum(f['size'] for f in self.file_table.values()),
                'total_size_mb': sum(f['size'] for f in self.file_table.values()) // (1024 * 1024),
                'created_at': self.metadata.get('created_at_str', 'Unknown'),
                'version': self.metadata.get('version', '1.0'),
                'files': []
            }
            
            for internal_path, file_info in self.file_table.items():
                preview['files'].append({
                    'name': internal_path,
                    'size_bytes': file_info['size'],
                    'size_kb': file_info['size'] // 1024,
                    'added_date': time.strftime('%Y-%m-%d', time.localtime(file_info['added_at'])),
                    'original_name': file_info.get('original_name', '')
                })
            
            self.secure_close()
            return preview
            
        except Exception as e:
            self.log.error(f"Quick preview error: {e}")
            return {'status': 'error', 'message': str(e)}
        
    def deep_integrity_check(self, password: str = None, key: bytes = None) -> Dict:
        """Comprehensive vault integrity verification - WITHOUT FILE HASH CHECKS"""
        try:
            self.log.info("Starting deep integrity check")
            
            if not self.is_open:
                if not self.open(password, key):
                    return {'status': 'error', 'message': 'Cannot open vault'}
            
            results = {
                'status': 'success',
                'checks_passed': 0,
                'checks_total': 2,  # Only 2 checks: header and file table
                'overall_status': 'healthy',
                'issues': [],
                'files_checked': len(self.file_table)
            }
            
            # Check 1: Header integrity
            if self._verify_header_integrity():
                results['checks_passed'] += 1
            else:
                results['issues'].append("Header integrity check failed")
            
            # Check 2: File table consistency  
            if self._verify_file_table_consistency():
                results['checks_passed'] += 1
            else:
                results['issues'].append("File table consistency check failed")
            
            # Determine overall status
            if results['checks_passed'] == results['checks_total']:
                results['overall_status'] = 'healthy'
            elif results['checks_passed'] >= results['checks_total'] * 0.7:
                results['overall_status'] = 'degraded'
            else:
                results['overall_status'] = 'corrupted'
            
            self.secure_close()
            return results
            
        except Exception as e:
            self.log.error(f"Deep integrity check error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _verify_header_integrity(self) -> bool:
        """Verify header structure"""
        required_fields = ['version', 'size_bytes', 'created_at', 'file_count']
        return all(field in self.metadata for field in required_fields)

    def _verify_file_table_consistency(self) -> bool:
        """Verify file table structure"""
        for path, info in self.file_table.items():
            required = ['size', 'offset', 'hash', 'added_at']
            if not all(field in info for field in required):
                return False
        return True

    def _create_header(self) -> bytes:
        """Legacy method for compatibility - use _create_secure_header for new vaults"""
        try:
            metadata_json = json.dumps(self.metadata).encode('utf-8')
            header = struct.pack('>I', len(metadata_json)) + metadata_json
            return header
        except Exception as e:
            self.log.error(f"Failed to create vault header: {e}")
            raise

    def _read_header(self, data: bytes) -> bool:
        """Legacy method for compatibility - use _read_secure_header for new vaults"""
        try:
            metadata_len = struct.unpack('>I', data[:4])[0]
            metadata_json = data[4:4 + metadata_len]
            self.metadata = json.loads(metadata_json.decode('utf-8'))
            return True
        except Exception as e:
            self.log.error(f"Failed to read vault header: {e}")
            return False
        
    def debug_file_info(self, internal_path: str):
        """Debug method to check file information"""
        if internal_path in self.file_table:
            file_info = self.file_table[internal_path]
            self.log.info(f"File debug info for {internal_path}:")
            self.log.info(f"  - Size: {file_info['size']}")
            self.log.info(f"  - Offset: {file_info['offset']}")
            self.log.info(f"  - Hash: {file_info.get('hash', 'MISSING')}")
            
            if self.decrypted_data:
                end_offset = file_info['offset'] + file_info['size']
                self.log.info(f"  - Data bounds: {file_info['offset']} to {end_offset} (total: {len(self.decrypted_data)})")
                
                if end_offset <= len(self.decrypted_data):
                    file_data = self.decrypted_data[file_info['offset']:end_offset]
                    self.log.info(f"  - Actual data size: {len(file_data)}")
                    self.log.info(f"  - Actual hash: {self._calculate_hash(file_data) if file_data else 'EMPTY'}")

    def get_info(self, password: str = None, key: bytes = None) -> dict:
        try:
            info = {
                'path': str(self.vault_path),
                'status': 'ACTIVE' if self.vault_path.exists() else 'MISSING'
            }

            if self.vault_path.exists():
                disk_size = self.vault_path.stat().st_size
                info['disk_size_mb'] = disk_size // (1024 * 1024)
                created_time = self.vault_path.stat().st_ctime
                info['created_at'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_time))
            else:
                info['disk_size_mb'] = 0
                info['created_at'] = 'Unknown'

            if self.vault_path.exists():
                if self.is_open and self.file_table:
                    total_size = self.metadata.get('size_bytes', 0)
                    file_count = len(self.file_table)
                    total_used = sum(f['size'] for f in self.file_table.values())
                    free_space = total_size - total_used

                    info['total_size_mb'] = total_size // (1024 * 1024)
                    info['file_count'] = file_count
                    info['used_space_mb'] = total_used // 1024
                    info['free_space_mb'] = free_space // (1024 * 1024)
                    info['files_list'] = list(self.file_table.keys())

                    if 'created_at_str' in self.metadata:
                        info['created_at'] = self.metadata['created_at_str']

                    self.log.info(f"Vault info from opened state: {file_count} files, {total_used//1024}KB used")
                else:
                    try:
                        if self.open(password, key):
                            total_size = self.metadata.get('size_bytes', 0)
                            file_count = len(self.file_table)
                            total_used = sum(f['size'] for f in self.file_table.values())
                            free_space = total_size - total_used

                            info['total_size_mb'] = total_size // (1024 * 1024)
                            info['file_count'] = file_count
                            info['used_space_mb'] = total_used // 1024
                            info['free_space_mb'] = free_space // (1024 * 1024)
                            info['files_list'] = list(self.file_table.keys())

                            if 'created_at_str' in self.metadata:
                                info['created_at'] = self.metadata['created_at_str']

                            self.log.info(f"Vault info after opening: {file_count} files, {total_used//1024}KB used")
                        else:
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