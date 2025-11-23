import time
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional

from obfutil.crypto.encryption import decrypt_data, encrypt_data
from obfutil.vault.container import VaultContainer
from obfutil.utils.logger import get_logger
from obfutil.config import VAULTS_DIR

class VaultManager:
    def __init__(self, vaults_dir: str = None):
        self.vaults_dir = Path(vaults_dir) if vaults_dir else VAULTS_DIR
        self.vaults_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.vaults_dir / "vaults.json"
        self.log = get_logger("VAULT_MANAGER")
        self._load_config()
        self.open_vaults = {}  # Cache of opened vaults
    
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
                # Save to config
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
    
    def open_vault(self, name: str, password: str = None, key: bytes = None) -> Optional[VaultContainer]:
        """Open vault for file operations with password verification"""
        try:
            if name not in self.config:
                self.log.error(f"Vault not found in config: {name}")
                return None

            vault_path = Path(self.config[name]['path'])
            if not vault_path.exists():
                self.log.error(f"Vault file not found: {vault_path}")
                return None

            # Check if vault is already open
            if name in self.open_vaults:
                vault = self.open_vaults[name]
                if vault.is_open:
                    return vault

            vault = VaultContainer(vault_path)
            if vault.open(password, key):
                self.log.info(f"Vault '{name}' opened successfully")
                self.open_vaults[name] = vault  # Save to cache
                return vault
            else:
                self.log.error(f"Failed to open vault '{name}' - invalid password or corrupted")
                return None

        except Exception as e:
            self.log.error(f"Error opening vault '{name}': {e}")
            return None

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

            # Get list of files in vault
            files_in_vault = vault.list_files()
            self.log.info(f"Vault '{name}' contains {len(files_in_vault)} files")

            output = Path(output_path)
            self.log.info(f"Attempting to extract: {internal_path} -> {output_path}")
            success = vault.extract_file(internal_path, output, password, key)

            if success:
                self.log.info(f"File extracted successfully from vault '{name}'")
            else:
                self.log.error(f"Extraction failed for file '{internal_path}' in vault '{name}'")

            return success

        except Exception as e:
            self.log.error(f"Error extracting file from vault '{name}': {e}")
            return False

    def list_files_in_vault(self, name: str, password: str = None, key: bytes = None) -> Optional[List[str]]:
        """Return list of files in vault. Returns None if vault cannot be opened"""
        try:
            vault = self.open_vault(name, password, key)
            if not vault:
                self.log.warning(f"Vault '{name}' could not be opened")
                return None
        
            files = vault.list_files()
            self.log.info(f"Found {len(files)} files in vault '{name}'")
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
            
            return success
            
        except Exception as e:
            self.log.error(f"Error removing file from vault '{name}': {e}")
            return False

    def list_vaults(self) -> List[Dict]:
        """Return minimal information about vaults"""
        try:
            vaults = []
            for name, info in self.config.items():
                vault_path = Path(info['path'])

                # Minimal information without details
                vault_info = {
                    'name': name,
                    'status': 'ACTIVE' if vault_path.exists() else 'MISSING',
                    'size_mb': info.get('size_mb', 0),
                }

                vaults.append(vault_info)

            self.log.info(f"Listed {len(vaults)} vault(s)")
            return vaults

        except Exception as e:
            self.log.error(f"Error listing vaults: {e}")
            return []

    def get_vault_info(self, name: str, password: str = None, key: bytes = None) -> Dict:
        """Return information about specific vault"""
        try:
            if name not in self.config:
                self.log.warning(f"Vault not found in config: {name}")
                return {}

            vault_path = Path(self.config[name]['path'])
            if not vault_path.exists():
                self.log.warning(f"Vault file not found: {vault_path}")
                return {}

            vault = VaultContainer(self.config[name]['path'])

            # Use get_info with password for detailed information
            info = vault.get_info(password, key)
            self.log.info(f"Retrieved info for vault: {name} - {info.get('file_count', 0)} files, {info.get('used_space_mb', 0)}MB used")
            return info

        except Exception as e:
            self.log.error(f"Error getting vault info for '{name}': {e}")
            return {}

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
            
            # Remove from open vaults cache
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
                return vault.file_table[internal_path]
            return {}

        except Exception as e:
            self.log.error(f"Error getting file info for '{internal_path}' in vault '{name}': {e}")
            return {}