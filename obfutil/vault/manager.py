"""
Vault Manager - Manages vault operations
Version 3.4: Added support for new container features:
- Space checking
- File rename
- Search functionality  
- Folder usage statistics
- Force overwrite option
"""

import time
import json
from pathlib import Path
from typing import List, Dict, Optional, Callable, Tuple

from obfutil.crypto.encryption import decrypt_data, encrypt_data
from obfutil.vault.container import VaultContainer
from obfutil.utils.logger import get_logger
from obfutil.config import VAULTS_DIR


class VaultManager:
    """
    Enhanced vault manager with V3.4 features
    
    New in 3.4:
    - Space checking before file operations
    - File rename capability
    - Advanced search with filters
    - Folder usage statistics
    - Force overwrite option for add
    """
    
    def __init__(self, vaults_dir: str = None):
        self.log = get_logger("VLT_MANAGER")
        self.vaults_dir = Path(vaults_dir) if vaults_dir else VAULTS_DIR
        self.vaults_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.vaults_dir / "vaults.json"
        self._load_config()
        self.open_vaults = {}
    
    def _load_config(self):
        """Load vaults configuration"""
        try:
            if self.config_file.exists():
                self.config = json.loads(self.config_file.read_text())
                self.log.info(f"Loaded vault config: {len(self.config)} vault(s)")
            else:
                self.config = {}
                self.log.info("No vault config found, creating new one")
        except Exception as e:
            self.log.error(f"Failed to load vault config: {e}")
            self.config = {}

    def _save_config(self):
        """Save vaults configuration"""
        try:
            self.config_file.write_text(json.dumps(self.config, indent=2))
        except Exception as e:
            self.log.error(f"Failed to save vault config: {e}")
            raise
    
    def secure_operation(self, name: str, operation: Callable, 
                       password: str = None, key: bytes = None,
                       auto_cleanup: bool = True) -> Optional[any]:
        """
        Execute vault operation with guaranteed memory cleanup
        
        Args:
            name: Vault name
            operation: Function to execute with opened vault
            password: Password for authentication
            key: Key file for authentication
            auto_cleanup: Whether to close vault after operation
            
        Returns:
            Result of operation or None if failed
        """
        vault = None
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.error(f"Failed to open vault: {name}")
                return None
            
            result = operation(vault)
            return result
            
        except Exception as e:
            self.log.error(f"Secure operation failed for '{name}': {e}")
            return None
            
        finally:
            if vault and auto_cleanup:
                vault.secure_close()
                if name in self.open_vaults:
                    del self.open_vaults[name]
    
    # ========== NEW METHODS FOR 3.4 ==========
    
    def check_vault_space(self, name: str, file_size: int, 
                          old_path: str = None,
                          password: str = None, key: bytes = None) -> Tuple[bool, int]:
        """
        Check if vault has enough space for a file
        
        Args:
            name: Vault name
            file_size: Size of file to add in bytes
            old_path: If overwriting, path of file to replace
            password: Password for authentication
            key: Key file for authentication
            
        Returns:
            Tuple[bool, int]: (has_space, free_space_bytes)
        """
        def check_op(vault):
            used_space = sum(f['size'] for f in vault.file_table.values())
            
            # If replacing, subtract old file size
            if old_path and old_path in vault.file_table:
                used_space -= vault.file_table[old_path]['size']
            
            total_space = vault.metadata.get('size_bytes', 0)
            free_space = total_space - used_space
            # Reserve 1KB for metadata overhead
            required_space = file_size + 1024
            
            return free_space >= required_space, free_space
        
        result = self.secure_operation(name, check_op, password, key)
        return result if result else (False, 0)
    
    def rename_file_in_vault(self, name: str, old_path: str, new_path: str,
                         password: str = None, key: bytes = None) -> bool:
        """
        Rename a file inside the vault
        
        Args:
            name: Vault name
            old_path: Current internal path
            new_path: New internal path
            password: Password for authentication
            key: Key file for authentication
            
        Returns:
            bool: True if rename successful
        """
        # Validate new path (no leading/trailing slashes, no empty)
        if not new_path or new_path.startswith('/') or new_path.endswith('/'):
            self.log.error(f"Invalid new path: {new_path}")
            return False
        
        def rename_op(vault):
            # Pass the credentials to vault.rename_file
            return vault.rename_file(old_path, new_path, password, key)
        
        result = self.secure_operation(name, rename_op, password, key)
        
        if result:
            self.log.info(f"File renamed in vault '{name}': {old_path} -> {new_path}")
        else:
            self.log.error(f"Failed to rename file in vault '{name}'")
        
        return result or False
    
    def search_files_in_vault(self, name: str, pattern: str, 
                                search_type: str = 'name',
                                case_sensitive: bool = False,
                                min_size: int = None,
                                max_size: int = None,
                                password: str = None, key: bytes = None) -> List[Dict]:
        """
        Search for files in vault with optional filters
        
        Args:
            name: Vault name
            pattern: Search pattern
            search_type: 'name' (wildcards), 'contains', 'ext'
            case_sensitive: Whether search is case-sensitive
            min_size: Minimum file size in bytes
            max_size: Maximum file size in bytes
            password: Password for authentication
            key: Key file for authentication
            
        Returns:
            List[Dict]: List of matching files with details
        """
        def search_op(vault):
            results = []
            
            for path, info in vault.file_table.items():
                file_size = info.get('size', 0)
                
                # Size filters - если размер None, пропускаем фильтр
                if min_size is not None and file_size < min_size:
                    continue
                if max_size is not None and file_size > max_size:
                    continue
                
                # Apply name matching
                match_path = path if case_sensitive else path.lower()
                match_pattern = pattern if case_sensitive else pattern.lower()
                
                match = False
                if search_type == 'name':
                    import fnmatch
                    if fnmatch.fnmatch(match_path, match_pattern):
                        match = True
                elif search_type == 'contains':
                    if match_pattern in match_path:
                        match = True
                elif search_type == 'ext':
                    ext = path.split('.')[-1].lower() if '.' in path else ''
                    if match_pattern == ext:
                        match = True
                
                if match:
                    results.append({
                        'path': path,
                        'size_bytes': info['size'],
                        'size_kb': info['size'] // 1024,
                        'size_mb': round(info['size'] / (1024 * 1024), 2),
                        'added_at': info.get('added_at', 0),
                        'added_date': time.strftime('%Y-%m-%d %H:%M:%S', 
                                                   time.localtime(info.get('added_at', 0))),
                        'original_name': info.get('original_name', '')
                    })
            
            # Sort by path for consistent output
            results.sort(key=lambda x: x['path'])
            return results
        
        result = self.secure_operation(name, search_op, password, key)
        return result if result else []
    
    def get_vault_folder_usage(self, name: str, 
                              password: str = None, key: bytes = None) -> Dict[str, int]:
        """
        Get storage usage by folder
        
        Args:
            name: Vault name
            password: Password for authentication
            key: Key file for authentication
            
        Returns:
            Dict[str, int]: Folder path -> size in bytes
        """
        def usage_op(vault):
            return vault.get_folder_usage()
        
        result = self.secure_operation(name, usage_op, password, key)
        return result if result else {}
    
    def get_vault_statistics(self, name: str,
                            password: str = None, key: bytes = None) -> Dict:
        """
        Get detailed vault statistics
        
        Args:
            name: Vault name
            password: Password for authentication
            key: Key file for authentication
            
        Returns:
            Dict: Comprehensive vault statistics
        """
        def stats_op(vault):
            stats = vault.get_vault_statistics()
            
            # Add folder summary
            folder_usage = vault.get_folder_usage()
            sorted_folders = sorted(folder_usage.items(), key=lambda x: x[1], reverse=True)[:10]
            
            stats['folder_summary'] = [
                {
                    'path': folder,
                    'size_bytes': size,
                    'size_mb': round(size / (1024 * 1024), 2),
                    'size_percent': round((size / stats['total_size_bytes']) * 100, 1) 
                                    if stats['total_size_bytes'] > 0 else 0
                }
                for folder, size in sorted_folders
            ]
            
            # Add top 10 largest files
            all_files = [(path, info['size']) for path, info in vault.file_table.items()]
            top_files = sorted(all_files, key=lambda x: x[1], reverse=True)[:10]
            
            stats['top_10_files'] = [
                {
                    'path': path,
                    'size_bytes': size,
                    'size_mb': round(size / (1024 * 1024), 2)
                }
                for path, size in top_files
            ]
            
            return stats
        
        result = self.secure_operation(name, stats_op, password, key)
        return result if result else {}
    
    # ========== MODIFIED METHODS FOR 3.4 ==========
    
    def add_file_to_vault(self, name: str, file_path: str, internal_path: str = None, 
                         password: str = None, key: bytes = None, 
                         move: bool = False, force: bool = False) -> bool:
        """
        Add file to vault with 3.4 enhancements
        
        Args:
            name: Vault name
            file_path: Source file path
            internal_path: Target path inside vault
            password: Password for authentication
            key: Key file for authentication
            move: Delete original file after adding
            force: Overwrite existing file if exists
            
        Returns:
            bool: True if successful
        """
        try:
            # Check if source file exists
            source_path = Path(file_path)
            if not source_path.exists():
                self.log.warning(f"Source file not found: {file_path}")
                print(f"ERROR: Source file not found: {file_path}")
                return False
            
            # Check if vault exists
            if name not in self.config:
                self.log.error(f"Vault not found: {name}")
                print(f"ERROR: Vault '{name}' not found!")
                return False
            
            # Generate internal path if not provided
            if not internal_path:
                internal_path = source_path.name
            
            # Check if file already exists (for better error message)
            preview = self.quick_vault_preview(name, password, key)
            if preview.get('status') == 'success':
                existing_files = [f['name'] for f in preview.get('files', [])]
                if internal_path in existing_files and not force:
                    print(f"ERROR: File '{internal_path}' already exists in vault")
                    print("Use --force to overwrite")
                    return False
            
            # Check available space
            file_size = source_path.stat().st_size
            has_space, free_space = self.check_vault_space(
                name, file_size, internal_path if force else None, 
                password, key
            )
            
            if not has_space:
                print(f"ERROR: Not enough space in vault")
                print(f"  Need: {file_size / (1024*1024):.1f} MB")
                print(f"  Free: {free_space / (1024*1024):.1f} MB")
                return False
            
            # Open vault and add file
            vault = self.open_vault(name, password, key)
            if not vault:
                print(f"ERROR: Failed to open vault - wrong password or corrupted")
                return False
            
            self.log.info(f"Adding file to vault '{name}': {file_path} -> {internal_path}")
            success = vault.add_file(source_path, internal_path, password, key, force=force)
            
            if success:
                self.log.info(f"File added successfully to vault '{name}'")
                print(f"SUCCESS: File added to vault '{name}'")
                
                if move:
                    try:
                        source_path.unlink()
                        self.log.info(f"Original file deleted: {file_path}")
                        print(f"  Original file deleted")
                    except Exception as e:
                        self.log.error(f"Failed to delete original file: {e}")
                        print(f"WARNING: File added but original could not be deleted: {e}")
            else:
                self.log.error(f"Failed to add file to vault '{name}'")
                print(f"ERROR: Failed to add file")
                print("Possible reasons:")
                print("  - Wrong password or key")
                print("  - Vault is corrupted")
                print("  - Not enough space (check with 'vault storage')")
                print("  - File already exists (use --force to overwrite)")
            
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
            
            return success
            
        except Exception as e:
            self.log.error(f"Error adding file to vault '{name}': {e}")
            print(f"ERROR: {e}")
            return False
    
    # ========== EXISTING METHODS (unchanged, kept for compatibility) ==========
    
    def quick_vault_preview(self, name: str, password: str = None, key: bytes = None) -> Dict:
        """Get vault overview without loading file data"""
        def preview_op(vault):
            return vault.quick_preview()
        return self.secure_operation(name, preview_op, password, key) or {}
    
    def verify_vault_integrity(self, name: str, password: str = None, 
                               key: bytes = None, deep_check: bool = False) -> Dict:
        """Verify vault integrity"""
        def integrity_op(vault):
            if deep_check:
                return vault.deep_integrity_check()
            else:
                header_ok = vault._verify_header_integrity()
                file_table_ok = vault._verify_file_table_consistency()
                return {
                    'status': 'success',
                    'check_type': 'quick',
                    'header_ok': header_ok,
                    'file_table_ok': file_table_ok,
                    'file_count': len(vault.file_table),
                    'overall_ok': header_ok and file_table_ok,
                    'overall_status': 'healthy' if (header_ok and file_table_ok) else 'degraded'
                }
        result = self.secure_operation(name, integrity_op, password, key)
        return result or {'status': 'error', 'message': 'Failed to access vault'}
    
    def check_vault_storage(self, name: str, password: str = None, key: bytes = None) -> Dict:
        """Check vault storage usage"""
        def storage_op(vault):
            total_size = vault.metadata.get('size_bytes', 0)
            used_space = sum(f['size'] for f in vault.file_table.values())
            free_space = total_size - used_space
            return {
                'status': 'ok',
                'total_size_mb': total_size // (1024 * 1024),
                'used_space_mb': used_space // (1024 * 1024),
                'free_space_mb': free_space // (1024 * 1024),
                'usage_percentage': (used_space / total_size * 100) if total_size > 0 else 0,
                'file_count': len(vault.file_table),
            }
        result = self.secure_operation(name, storage_op, password, key)
        return result or {'status': 'error', 'message': 'Failed to access vault'}
    
    def secure_vault_delete(self, name: str) -> bool:
        """Securely delete vault with proper cleanup"""
        try:
            if name in self.open_vaults:
                self.open_vaults[name].secure_close()
                del self.open_vaults[name]
            
            if name in self.config:
                vault_path = Path(self.config[name]['path'])
                if vault_path.exists():
                    vault_path.unlink()
                    self.log.info(f"Deleted vault file: {vault_path}")
                
                del self.config[name]
                self._save_config()
                self.log.info(f"Vault '{name}' securely deleted")
                return True
            else:
                self.log.warning(f"Vault not found in config: {name}")
                return False
        except Exception as e:
            self.log.error(f"Error during secure vault deletion '{name}': {e}")
            return False
    
    def open_vault(self, name: str, password: str = None, key: bytes = None) -> Optional[VaultContainer]:
        """Enhanced vault opening with better error reporting"""
        try:
            if name not in self.config:
                self.log.error(f"Vault not found in config: {name}")
                return None

            vault_path = Path(self.config[name]['path'])
            if not vault_path.exists():
                self.log.error(f"Vault file not found: {vault_path}")
                return None

            # Use cached vault if available
            if name in self.open_vaults:
                vault = self.open_vaults[name]
                if vault.is_open and vault.vault_path == vault_path:
                    return vault
                else:
                    vault.secure_close()
                    del self.open_vaults[name]

            vault = VaultContainer(vault_path)
            if vault.open(password, key):
                self.log.info(f"Vault '{name}' opened successfully")
                self.open_vaults[name] = vault
                return vault
            else:
                self.log.error(f"Failed to open vault '{name}'")
                if password is not None:
                    self.log.warning(f"Possible wrong password for vault '{name}'")
                elif key is not None:
                    self.log.warning(f"Possible wrong key for vault '{name}'")
                return None

        except Exception as e:
            self.log.error(f"Error opening vault '{name}': {e}")
            return None
    
    def list_vaults(self) -> List[Dict]:
        """List all vaults with status"""
        try:
            vaults = []
            for name, info in self.config.items():
                vault_path = Path(info['path'])
                vault_info = {
                    'name': name,
                    'status': 'ACTIVE' if vault_path.exists() else 'MISSING',
                    'size_mb': info.get('size_mb', 0),
                    'created_at': info.get('created_at', 'Unknown'),
                    'path': str(vault_path),
                    'file_count': '?',
                    'health': 'unknown'
                }
                
                if vault_path.exists():
                    try:
                        vault = VaultContainer(vault_path)
                        if vault.open(None, None, quick_mode=True):
                            vault_info['file_count'] = len(vault.file_table)
                            vault_info['health'] = 'accessible'
                        else:
                            vault_info['health'] = 'locked'
                        vault.secure_close()
                    except Exception as e:
                        self.log.debug(f"Cannot access vault '{name}' metadata: {e}")
                        vault_info['health'] = 'locked'
                
                vaults.append(vault_info)

            self.log.info(f"Listed {len(vaults)} vault(s)")
            return vaults

        except Exception as e:
            self.log.error(f"Error listing vaults: {e}")
            return []
    
    def get_vault_info(self, name: str, password: str = None, key: bytes = None) -> Dict:
        """Get detailed vault information"""
        try:
            if name not in self.config:
                self.log.warning(f"Vault not found in config: {name}")
                return {}

            vault_path = Path(self.config[name]['path'])
            if not vault_path.exists():
                self.log.warning(f"Vault file not found: {vault_path}")
                return {}

            created_at_from_config = self.config[name].get('created_at', 'Unknown')
            preview = self.quick_vault_preview(name, password, key)
            
            if preview.get('status') == 'success':
                info = {
                    'path': str(vault_path),
                    'status': 'ACTIVE',
                    'created_at': created_at_from_config,
                    'file_count': preview.get('file_count', 0),
                    'total_size_mb': preview.get('total_size_mb', 0),
                    'files_list': [f['name'] for f in preview.get('files', [])],
                    'version': preview.get('version', '1.0'),
                    'secure_features': True
                }
                
                storage_info = self.check_vault_storage(name, password, key)
                info.update(storage_info)
                return info
            else:
                return {
                    'path': str(vault_path),
                    'status': 'ACTIVE' if vault_path.exists() else 'MISSING',
                    'created_at': created_at_from_config,
                    'file_count': 0,
                    'total_size_mb': self.config[name].get('size_mb', 0),
                    'files_list': [],
                    'secure_features': False
                }

        except Exception as e:
            self.log.error(f"Error getting vault info for '{name}': {e}")
            return {}

    def create_vault(self, name: str, size_mb: int = 100, 
                    password: str = None, key: bytes = None) -> bool:
        """Create new vault"""
        try:
            vault_path = self.vaults_dir / f"{name}.obfvault"
            
            if vault_path.exists():
                self.log.warning(f"Vault already exists: {vault_path}")
                return False
            
            self.log.info(f"Creating new vault: {name} ({size_mb}MB) at {vault_path}")
            vault = VaultContainer(vault_path)
            success = vault.create(size_mb, password, key)
            
            if success:
                created_at = vault.metadata.get('created_at_str', time.strftime('%Y-%m-%d %H:%M:%S'))
                self.config[name] = {
                    'path': str(vault_path),
                    'size_mb': size_mb,
                    'created_at': created_at,
                    'created_timestamp': time.time()
                }
                self._save_config()
                self.log.info(f"Vault '{name}' created successfully")
                return True
            else:
                self.log.warning(f"Failed to create vault '{name}'")
                return False
                
        except Exception as e:
            self.log.error(f"Unexpected error creating vault '{name}': {e}")
            return False

    def extract_file_from_vault(self, name: str, internal_path: str, output_path: str,
                            password: str = None, key: bytes = None) -> bool:
        """Extract file from vault"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.error(f"Failed to open vault: {name}")
                print(f"ERROR: Failed to open vault - wrong password or corrupted")
                return False

            # Проверяем существование файла
            if internal_path not in vault.file_table:
                self.log.error(f"File not found in vault: {internal_path}")
                print(f"ERROR: File '{internal_path}' not found in vault")
                print(f"Use 'obfutil vault preview {name}' to see available files")
                return False

            output = Path(output_path)
            
            # Проверяем директорию
            output.parent.mkdir(parents=True, exist_ok=True)
            
            self.log.debug(f"Attempting to extract: {internal_path} -> {output_path}")
            success = vault.extract_file(internal_path, output, password, key)

            if success:
                self.log.info(f"File extracted successfully from vault '{name}'")
                print(f"  SUCCESS: File extracted to {output_path}")
            else:
                self.log.error(f"Extraction failed for file '{internal_path}'")
                print(f"  ERROR: Failed to extract file")
                print("Possible reasons:")
                print("  - File is corrupted")
                print("  - Wrong password (but vault opened, so unlikely)")
                print("  - File data integrity issue")

            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]

            return success

        except Exception as e:
            self.log.error(f"Error extracting file from vault '{name}': {e}")
            print(f"ERROR: {e}")
            return False

    def list_files_in_vault(self, name: str, password: str = None, key: bytes = None) -> Optional[List[str]]:
        """Return list of files in vault"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.warning(f"Vault '{name}' could not be opened")
                return None
        
            files = vault.list_files()
            self.log.info(f"Found {len(files)} files in vault '{name}'")
            
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
            return files

        except Exception as e:
            self.log.error(f"Error listing files in vault '{name}': {e}")
            return None

    def remove_file_from_vault(self, name: str, internal_path: str,
                               password: str = None, key: bytes = None) -> bool:
        """Remove file from vault"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.error(f"Failed to open vault: {name}")
                return False
            
            self.log.info(f"Removing file from vault '{name}': {internal_path}")
            success = vault.remove_file(internal_path, password, key)
            
            if success:
                self.log.info(f"File removed successfully from vault '{name}'")
                print(f"SUCCESS: File removed from vault '{name}'")
            else:
                self.log.error(f"Failed to remove file from vault '{name}'")
                print(f"ERROR: Failed to remove file - check path and try again")
            
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
            return success
            
        except Exception as e:
            self.log.error(f"Error removing file from vault '{name}': {e}")
            print(f"ERROR: {e}")
            return False

    def vault_exists(self, name: str) -> bool:
        """Check if vault exists"""
        if name not in self.config:
            return False
        exists = Path(self.config[name]['path']).exists()
        if not exists:
            self.log.debug(f"Vault file not found: {self.config[name]['path']}")
        return exists
        
    def delete_vault(self, name: str) -> bool:
        """Delete vault"""
        try:
            if name not in self.config:
                self.log.warning(f"Vault not found in config: {name}")
                return False
            
            vault_path = Path(self.config[name]['path'])
            
            if vault_path.exists():
                vault_path.unlink()
                self.log.info(f"Deleted vault file: {vault_path}")
            
            if name in self.open_vaults:
                del self.open_vaults[name]
            
            del self.config[name]
            self._save_config()
            self.log.info(f"Vault '{name}' deleted successfully")
            return True
            
        except Exception as e:
            self.log.error(f"Error deleting vault '{name}': {e}")
            return False
        
    def get_file_info(self, name: str, internal_path: str, 
                      password: str = None, key: bytes = None) -> Dict:
        """Return information about specific file in vault"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                return {}

            if internal_path in vault.file_table:
                info = vault.file_table[internal_path].copy()
                vault.secure_close()
                if name in self.open_vaults:
                    del self.open_vaults[name]
                return info
                
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
            return {}

        except Exception as e:
            self.log.error(f"Error getting file info for '{internal_path}' in vault '{name}': {e}")
            return {}