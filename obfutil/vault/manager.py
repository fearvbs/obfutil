import time
import json
from pathlib import Path
from typing import List, Dict, Optional, Callable

from obfutil.crypto.encryption import decrypt_data, encrypt_data
from obfutil.vault.container import VaultContainer
from obfutil.utils.logger import get_logger
from obfutil.config import VAULTS_DIR

class VaultManager:
    """
    Enhanced vault manager with V3.2 features
    """
    
    def __init__(self, vaults_dir: str = None):
        self.vaults_dir = Path(vaults_dir) if vaults_dir else VAULTS_DIR
        self.vaults_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.vaults_dir / "vaults.json"
        self.log = get_logger("VAULT_MANAGER")
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
    
    def quick_vault_preview(self, name: str, password: str = None, key: bytes = None) -> Dict:
        """Get vault overview without loading file data"""
        def preview_op(vault):
            return vault.quick_preview()
        
        return self.secure_operation(name, preview_op, password, key) or {}
    
    def get_vault_health(self, name: str, password: str = None, key: bytes = None) -> Dict:
        """Get vault health status - SIMPLIFIED VERSION"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                return {'status': 'unhealthy', 'message': 'Cannot open vault'}
            
            health_info = {
                'status': 'healthy',
                'file_count': len(vault.file_table),
                'total_size': sum(f['size'] for f in vault.file_table.values()),
                'metadata_ok': bool(vault.metadata)
            }
            
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
                
            return health_info
            
        except Exception as e:
            self.log.error(f"Health check error for '{name}': {e}")
            return {'status': 'error', 'message': str(e)}
    
    def verify_vault_integrity(self, name: str, password: str = None, 
                         key: bytes = None, deep_check: bool = False) -> Dict:
        """Verify vault integrity - FIXED quick check"""
        def integrity_op(vault):
            if deep_check:
                return vault.deep_integrity_check()
            else:
                # Quick check - verify basic structure
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
        """Check vault storage usage - FIXED VERSION"""
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

            # Use cached vault if available and still open
            if name in self.open_vaults:
                vault = self.open_vaults[name]
                if vault.is_open and vault.vault_path == vault_path:
                    return vault
                else:
                    # Clean up stale vault
                    vault.secure_close()
                    del self.open_vaults[name]

            vault = VaultContainer(vault_path)
            if vault.open(password, key):
                self.log.info(f"Vault '{name}' opened successfully")
                self.open_vaults[name] = vault
                return vault
            else:
                self.log.error(f"Failed to open vault '{name}' - check password/key and vault integrity")
                # Log additional debug info
                self.log.debug(f"Vault path: {vault_path}")
                self.log.debug(f"Vault exists: {vault_path.exists()}")
                self.log.debug(f"Vault size: {vault_path.stat().st_size if vault_path.exists() else 0} bytes")
                return None

        except Exception as e:
            self.log.error(f"Error opening vault '{name}': {e}")
            return None
    
    def list_vaults(self) -> List[Dict]:
        """Enhanced vault listing - FIXED VERSION"""
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
                    'file_count': '?',  # Default to unknown
                    'health': 'unknown'
                }
                
                if vault_path.exists():
                    try:
                        # Quick metadata check without authentication
                        vault = VaultContainer(vault_path)
                        if vault.open(None, None, quick_mode=True):
                            vault_info['file_count'] = len(vault.file_table)
                            vault_info['health'] = 'accessible'
                        else:
                            vault_info['health'] = 'locked'  # Requires password
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
        """Enhanced vault information with security features"""
        try:
            if name not in self.config:
                self.log.warning(f"Vault not found in config: {name}")
                return {}

            vault_path = Path(self.config[name]['path'])
            if not vault_path.exists():
                self.log.warning(f"Vault file not found: {vault_path}")
                return {}

            preview = self.quick_vault_preview(name, password, key)
            if preview.get('status') == 'success':
                info = {
                    'path': str(vault_path),
                    'status': 'ACTIVE',
                    'created_at': preview.get('created_at', 'Unknown'),
                    'file_count': preview.get('file_count', 0),
                    'total_size_mb': preview.get('total_size_mb', 0),
                    'files_list': [f['name'] for f in preview.get('files', [])],
                    'version': preview.get('version', '1.0'),
                    'secure_features': True
                }
                
                storage_info = self.check_vault_storage(name, password, key)
                info.update(storage_info)
                
                self.log.info(f"Retrieved enhanced info for vault: {name}")
                return info
            else:
                return {
                    'path': str(vault_path),
                    'status': 'ACTIVE' if vault_path.exists() else 'MISSING',
                    'file_count': 0,
                    'secure_features': False
                }

        except Exception as e:
            self.log.error(f"Error getting vault info for '{name}': {e}")
            return {}

    def create_vault(self, name: str, size_mb: int = 100, 
                    password: str = None, key: bytes = None) -> bool:
        """Create new vault using enhanced security features"""
        try:
            vault_path = self.vaults_dir / f"{name}.obfvault"
            
            if vault_path.exists():
                self.log.warning(f"Vault already exists: {vault_path}")
                return False
            
            self.log.info(f"Creating new vault: {name} ({size_mb}MB) at {vault_path}")
            vault = VaultContainer(vault_path)
            success = vault.create(size_mb, password, key)
            
            if success:
                self.config[name] = {
                    'path': str(vault_path),
                    'size_mb': size_mb,
                    'created_at': vault.metadata['created_at_str']
                }
                self._save_config()
                self.log.info(f"Vault '{name}' created successfully")
                return True
            else:
                self.log.error(f"Failed to create vault '{name}'")
                return False
                
        except Exception as e:
            self.log.error(f"Unexpected error creating vault '{name}': {e}")
            return False

    def add_file_to_vault(self, name: str, file_path: str, internal_path: str = None, 
                         password: str = None, key: bytes = None, move: bool = False) -> bool:
        """Add file to vault"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.error(f"Failed to open vault: {name}")
                return False
            
            source_path = Path(file_path)
            if not internal_path:
                internal_path = source_path.name
            
            if not source_path.exists():
                self.log.error(f"Source file not found: {file_path}")
                return False
            
            self.log.info(f"Adding file to vault '{name}': {file_path} -> {internal_path}")
            success = vault.add_file(source_path, internal_path, password, key)
            
            if success:
                self.log.info(f"File added successfully to vault '{name}'")
                
                if move:
                    try:
                        source_path.unlink()
                        self.log.info(f"Original file deleted: {file_path}")
                    except Exception as e:
                        self.log.error(f"Failed to delete original file: {e}")
            else:
                self.log.error(f"Failed to add file to vault '{name}'")
            
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
            
            return success
            
        except Exception as e:
            self.log.error(f"Error adding file to vault '{name}': {e}")
            return False

    def extract_file_from_vault(self, name: str, internal_path: str, output_path: str,
                          password: str = None, key: bytes = None) -> bool:
        """Extract file from vault"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.error(f"Failed to open vault: {name}")
                return False

            files_in_vault = vault.list_files()
            self.log.info(f"Vault '{name}' contains {len(files_in_vault)} files")

            output = Path(output_path)
            self.log.info(f"Attempting to extract: {internal_path} -> {output_path}")
            success = vault.extract_file(internal_path, output, password, key)

            if success:
                self.log.info(f"File extracted successfully from vault '{name}'")
            else:
                self.log.error(f"Extraction failed for file '{internal_path}' in vault '{name}'")

            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]

            return success

        except Exception as e:
            self.log.error(f"Error extracting file from vault '{name}': {e}")
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
            else:
                self.log.error(f"Failed to remove file from vault '{name}'")
            
            vault.secure_close()
            if name in self.open_vaults:
                del self.open_vaults[name]
            
            return success
            
        except Exception as e:
            self.log.error(f"Error removing file from vault '{name}': {e}")
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
        
    def get_file_info(self, name: str, internal_path: str, password: str = None, key: bytes = None) -> Dict:
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