from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import os, time

class ObfUtilAPI:
    def __init__(self):
        from obfutil.utils.logger import get_logger
        self.log = get_logger("API")
    
    def encrypt_file(self, file_path: str, password: str = None, key: bytes = None, 
                    lang: str = "en") -> Dict[str, Any]:
        """Encrypt file via API"""
        try:
            from obfutil.crypto.encryption import encrypt_file as _encrypt
            result = _encrypt(file_path, password=password, key=key, lang=lang)
            return {
                'success': True,
                'output_path': file_path + '.enc',
                'message': f"File encrypted successfully: {file_path}.enc"
            }
        except Exception as e:
            self.log.error(f"API encrypt_file error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Encryption failed: {str(e)}"
            }
    
    def encrypt_file_with_integrity(self, file_path: str, password: str = None, 
                                  key: bytes = None, lang: str = "en") -> Dict[str, Any]:
        """Encrypt file with integrity check via API"""
        try:
            from obfutil.crypto.encryption import encrypt_file_with_integrity as _encrypt_int
            integrity_data = _encrypt_int(file_path, password=password, key=key, lang=lang)
            return {
                'success': True,
                'output_path': file_path + '.enc',
                'integrity_data': integrity_data,
                'message': f"File encrypted with integrity: {file_path}.enc"
            }
        except Exception as e:
            self.log.error(f"API encrypt_file_with_integrity error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Encryption with integrity failed: {str(e)}"
            }
    
    def decrypt_file(self, file_path: str, password: str = None, key: bytes = None,
                    edit_mode: bool = False, lang: str = "en") -> Dict[str, Any]:
        """Decrypt file via API"""
        try:
            from obfutil.crypto.encryption import decrypt_file as _decrypt
            result = _decrypt(file_path, password=password, key=key, edit_mode=edit_mode, lang=lang)
            return {
                'success': True,
                'message': "File decrypted successfully" if not edit_mode else "File decrypted for editing"
            }
        except Exception as e:
            self.log.error(f"API decrypt_file error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Decryption failed: {str(e)}"
            }
    
    def decrypt_file_with_integrity(self, file_path: str, password: str = None, key: bytes = None,
                                  edit_mode: bool = False, lang: str = "en") -> Dict[str, Any]:
        """Decrypt file with integrity verification via API"""
        try:
            from obfutil.crypto.encryption import decrypt_file_with_integrity as _decrypt_int
            result = _decrypt_int(file_path, password=password, key=key, edit_mode=edit_mode, lang=lang)
            return {
                'success': True,
                'message': "File decrypted with integrity verification"
            }
        except Exception as e:
            self.log.error(f"API decrypt_file_with_integrity error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Decryption with integrity failed: {str(e)}"
            }
    
    def verify_file_integrity(self, file_path: str, password: str = None, 
                            key: bytes = None, lang: str = "en") -> Dict[str, Any]:
        """Verify file integrity via API"""
        try:
            from obfutil.crypto.encryption import verify_file_integrity as _verify
            result = _verify(file_path, password=password, key=key, lang=lang)
            return {
                'success': True,
                'message': "File integrity verified successfully"
            }
        except Exception as e:
            self.log.error(f"API verify_file_integrity error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Integrity verification failed: {str(e)}"
            }
    
    def obfuscate_code(self, file_path: str, lang: str = "en") -> Dict[str, Any]:
        """Obfuscate code via API"""
        try:
            from obfutil.obfuscation.core import obfuscate_code as _obfuscate
            from obfutil.utils.file_utils import read_file_safe, write_file_safe
            
            code = read_file_safe(file_path)
            obfuscated = _obfuscate(code)
            
            output_path = file_path.replace('.py', '_obf.py')
            write_file_safe(output_path, obfuscated)
            
            return {
                'success': True,
                'output_path': output_path,
                'message': f"Code obfuscated successfully: {output_path}"
            }
        except Exception as e:
            self.log.error(f"API obfuscate_code error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Obfuscation failed: {str(e)}"
            }

    # VAULT OPERATIONS
    def create_vault(self, name: str, size_mb: int = 100, password: str = None,
                    key: bytes = None) -> Dict[str, Any]:
        """Create vault via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            success = manager.create_vault(name, size_mb, password, key)
            
            return {
                'success': success,
                'vault_name': name,
                'size_mb': size_mb,
                'message': f"Vault '{name}' created successfully" if success else f"Failed to create vault '{name}'"
            }
        except Exception as e:
            self.log.error(f"API create_vault error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Vault creation failed: {str(e)}"
            }
    
    def list_vaults(self) -> Dict[str, Any]:
        """List vaults via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            vaults = manager.list_vaults()
            
            return {
                'success': True,
                'vaults': vaults,
                'count': len(vaults),
                'message': f"Found {len(vaults)} vault(s)"
            }
        except Exception as e:
            self.log.error(f"API list_vaults error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to list vaults: {str(e)}"
            }
    
    def get_vault_info(self, name: str, password: str = None, key: bytes = None) -> Dict[str, Any]:
        """Get vault information via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            info = manager.get_vault_info(name, password, key)
            
            return {
                'success': True,
                'vault_name': name,
                'info': info,
                'message': f"Vault info retrieved for '{name}'"
            }
        except Exception as e:
            self.log.error(f"API get_vault_info error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to get vault info: {str(e)}"
            }
    
    def add_file_to_vault(self, vault_name: str, file_path: str, internal_path: str = None,
                         password: str = None, key: bytes = None, move: bool = False) -> Dict[str, Any]:
        """Add file to vault via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            success = manager.add_file_to_vault(vault_name, file_path, internal_path, password, key, move)
            
            return {
                'success': success,
                'vault_name': vault_name,
                'file_path': file_path,
                'internal_path': internal_path or Path(file_path).name,
                'message': f"File added to vault '{vault_name}'" if success else f"Failed to add file to vault '{vault_name}'"
            }
        except Exception as e:
            self.log.error(f"API add_file_to_vault error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to add file to vault: {str(e)}"
            }
    
    def extract_file_from_vault(self, vault_name: str, internal_path: str, output_path: str,
                              password: str = None, key: bytes = None) -> Dict[str, Any]:
        """Extract file from vault via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            success = manager.extract_file_from_vault(vault_name, internal_path, output_path, password, key)
            
            return {
                'success': success,
                'vault_name': vault_name,
                'internal_path': internal_path,
                'output_path': output_path,
                'message': f"File extracted from vault '{vault_name}'" if success else f"Failed to extract file from vault '{vault_name}'"
            }
        except Exception as e:
            self.log.error(f"API extract_file_from_vault error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to extract file from vault: {str(e)}"
            }
    
    def list_files_in_vault(self, vault_name: str, password: str = None, key: bytes = None) -> Dict[str, Any]:
        """List files in vault via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            files = manager.list_files_in_vault(vault_name, password, key)
            
            return {
                'success': files is not None,
                'vault_name': vault_name,
                'files': files or [],
                'count': len(files) if files else 0,
                'message': f"Found {len(files) if files else 0} files in vault '{vault_name}'" if files is not None else "Failed to access vault"
            }
        except Exception as e:
            self.log.error(f"API list_files_in_vault error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to list files in vault: {str(e)}"
            }
    
    def remove_file_from_vault(self, vault_name: str, internal_path: str,
                             password: str = None, key: bytes = None) -> Dict[str, Any]:
        """Remove file from vault via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            success = manager.remove_file_from_vault(vault_name, internal_path, password, key)
            
            return {
                'success': success,
                'vault_name': vault_name,
                'internal_path': internal_path,
                'message': f"File removed from vault '{vault_name}'" if success else f"Failed to remove file from vault '{vault_name}'"
            }
        except Exception as e:
            self.log.error(f"API remove_file_from_vault error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to remove file from vault: {str(e)}"
            }
    
    def delete_vault(self, vault_name: str) -> Dict[str, Any]:
        """Delete vault via API"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()
            success = manager.delete_vault(vault_name)
            
            return {
                'success': success,
                'vault_name': vault_name,
                'message': f"Vault '{vault_name}' deleted successfully" if success else f"Failed to delete vault '{vault_name}'"
            }
        except Exception as e:
            self.log.error(f"API delete_vault error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to delete vault: {str(e)}"
            }
    
    # UTILITY METHODS
    def generate_password(self, length: int = 12) -> Dict[str, Any]:
        """Generate password via API"""
        try:
            from obfutil.crypto.encryption import generate_password as _gen_pass
            password = _gen_pass(length)
            
            return {
                'success': True,
                'password': password,
                'length': length,
                'message': f"Generated {length}-character password"
            }
        except Exception as e:
            self.log.error(f"API generate_password error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Password generation failed: {str(e)}"
            }
    
    def generate_key_file(self, key_path: str = None) -> Dict[str, Any]:
        """Generate key file via API"""
        try:
            from obfutil.crypto.encryption import generate_key_file, DEFAULT_KEY_PATH
            key_path = key_path or DEFAULT_KEY_PATH
            key = generate_key_file(key_path)
            
            return {
                'success': True,
                'key_path': key_path,
                'message': f"Key file generated: {key_path}"
            }
        except Exception as e:
            self.log.error(f"API generate_key_file error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Key file generation failed: {str(e)}"
            }
    
    def encrypt_files_batch(self, file_paths: List[str], password: str = None, 
                       key: bytes = None, lang: str = "en") -> Dict[str, Any]:
        """Batch file encryption with detailed statistics"""
        try:
            results = {}
            total_size = 0
            processed_size = 0
            start_time = time.time()

            for file_path in file_paths:
                file_size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
                total_size += file_size
                result = self.encrypt_file(file_path, password, key, lang)
                results[file_path] = result
                if result['success']:
                    processed_size += file_size

            success_count = sum(1 for r in results.values() if r['success'])
            end_time = time.time()
            processing_time = end_time - start_time

            # Calculate speed (MB/s)
            speed_mb_s = (processed_size / (1024 * 1024)) / processing_time if processing_time > 0 else 0

            return {
                'success': True,
                'processed': len(file_paths),
                'successful': success_count,
                'failed': len(file_paths) - success_count,
                'total_size_bytes': total_size,
                'processed_size_bytes': processed_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'processed_size_mb': round(processed_size / (1024 * 1024), 2),
                'processing_time_seconds': round(processing_time, 2),
                'average_speed_mb_s': round(speed_mb_s, 2),
                'results': results,
                'message': f"Batch encryption completed: {success_count}/{len(file_paths)} files"
            }
        except Exception as e:
            self.log.error(f"API encrypt_files_batch error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Batch encryption failed: {str(e)}"
            }

    def decrypt_files_batch(self, file_paths: List[str], password: str = None,
                       key: bytes = None, lang: str = "en") -> Dict[str, Any]:
        """Batch file decryption with detailed statistics"""
        try:
            results = {}
            total_size = 0
            processed_size = 0
            start_time = time.time()

            for file_path in file_paths:
                file_size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
                total_size += file_size
                result = self.decrypt_file(file_path, password, key, False, lang)
                results[file_path] = result
                if result['success']:
                    processed_size += file_size

            success_count = sum(1 for r in results.values() if r['success'])
            end_time = time.time()
            processing_time = end_time - start_time

            # Calculate speed (MB/s)
            speed_mb_s = (processed_size / (1024 * 1024)) / processing_time if processing_time > 0 else 0

            return {
                'success': True,
                'processed': len(file_paths),
                'successful': success_count,
                'failed': len(file_paths) - success_count,
                'total_size_bytes': total_size,
                'processed_size_bytes': processed_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'processed_size_mb': round(processed_size / (1024 * 1024), 2),
                'processing_time_seconds': round(processing_time, 2),
                'average_speed_mb_s': round(speed_mb_s, 2),
                'results': results,
                'message': f"Batch decryption completed: {success_count}/{len(file_paths)} files"
            }
        except Exception as e:
            self.log.error(f"API decrypt_files_batch error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Batch decryption failed: {str(e)}"
            }

    def add_files_to_vault_batch(self, vault_name: str, files_mapping: Dict[str, str],
                               password: str = None, key: bytes = None, move: bool = False) -> Dict[str, Any]:
        """Batch file addition to vault"""
        try:
            results = {}
            for file_path, internal_path in files_mapping.items():
                results[file_path] = self.add_file_to_vault(
                    vault_name, file_path, internal_path, password, key, move
                )

            success_count = sum(1 for r in results.values() if r['success'])
            return {
                'success': True,
                'vault_name': vault_name,
                'processed': len(files_mapping),
                'successful': success_count,
                'failed': len(files_mapping) - success_count,
                'results': results,
                'message': f"Batch vault add: {success_count}/{len(files_mapping)} files added to '{vault_name}'"
            }
        except Exception as e:
            self.log.error(f"API add_files_to_vault_batch error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Batch vault add failed: {str(e)}"
            }
        
    def analyze_vault_usage(self, vault_name: str, password: str = None, key: bytes = None) -> Dict[str, Any]:
        """Analyze vault usage"""
        try:
            from obfutil.vault.manager import VaultManager
            manager = VaultManager()

            vault_info = manager.get_vault_info(vault_name, password, key)
            if not vault_info:
                return {
                    'success': False,
                    'message': f"Vault '{vault_name}' not found or inaccessible"
                }

            files_info = manager.list_files_in_vault(vault_name, password, key)
            total_files = len(files_info) if files_info else 0
            total_size = sum(file_info.get('size', 0) for file_info in (files_info or []))

            # Analyze file types
            file_types = self._analyze_file_types(files_info)

            # Calculate usage
            capacity_bytes = vault_info.get('size_mb', 0) * 1024 * 1024
            usage_percentage = (total_size / capacity_bytes) * 100 if capacity_bytes > 0 else 0

            return {
                'success': True,
                'vault_name': vault_name,
                'analysis': {
                    'total_files': total_files,
                    'total_size_bytes': total_size,
                    'total_size_mb': round(total_size / (1024 * 1024), 2),
                    'used_space_mb': round(total_size / (1024 * 1024), 2),
                    'capacity_mb': vault_info.get('size_mb', 0),
                    'free_space_mb': round((capacity_bytes - total_size) / (1024 * 1024), 2),
                    'usage_percentage': round(usage_percentage, 1),
                    'file_types': file_types,
                    'largest_file': self._find_largest_file(files_info),
                    'oldest_file': self._find_oldest_file(files_info),
                    'newest_file': self._find_newest_file(files_info)
                },
                'message': f"Vault analysis completed for '{vault_name}'"
            }
        except Exception as e:
            self.log.error(f"API analyze_vault_usage error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Vault analysis failed: {str(e)}"
            }
        
    def _analyze_file_types(self, files_info: List[Dict]) -> Dict[str, int]:
        """Analyze file types in vault"""
        from collections import defaultdict
        file_types = defaultdict(int)

        for file_info in (files_info or []):
            filename = file_info.get('name', '')
            if '.' in filename:
                ext = filename.split('.')[-1].lower()
                file_types[ext] += 1
            else:
                file_types['no_extension'] += 1

        return dict(file_types)

    def _find_largest_file(self, files_info: List[Dict]) -> Dict[str, Any]:
        """Find largest file"""
        if not files_info:
            return {}

        largest = max(files_info, key=lambda x: x.get('size', 0))
        return {
            'name': largest.get('name', ''),
            'size_bytes': largest.get('size', 0),
            'size_mb': round(largest.get('size', 0) / (1024 * 1024), 2)
        }

    def _find_oldest_file(self, files_info: List[Dict]) -> Dict[str, Any]:
        """Find oldest file"""
        if not files_info:
            return {}

        # Find file with earliest modification date
        oldest = min(files_info, key=lambda x: x.get('modified', float('inf')))
        return {
            'name': oldest.get('name', ''),
            'modified': oldest.get('modified', 0)
        }

    def _find_newest_file(self, files_info: List[Dict]) -> Dict[str, Any]:
        """Find newest file"""
        if not files_info:
            return {}

        newest = max(files_info, key=lambda x: x.get('modified', 0))
        return {
            'name': newest.get('name', ''),
            'modified': newest.get('modified', 0)
        }
            
    def get_config(self) -> Dict[str, Any]:
        """Get current system settings with proper paths"""
        try:
            from obfutil.config import load_config, DEFAULT_KEY_PATH, CONFIG_PATH, LOGS_DIR, VAULTS_DIR
            from pathlib import Path

            config = load_config()

            # Enhanced configuration with all paths
            enhanced_config = {
                **config,
                'paths': {
                    'config_file': str(CONFIG_PATH),
                    'key_file': str(DEFAULT_KEY_PATH),
                    'logs_directory': str(LOGS_DIR),
                    'vaults_directory': str(VAULTS_DIR),
                    'app_data_directory': str(LOGS_DIR.parent)  # .obfutil directory
                },
                'key_file_status': {
                    'exists': Path(DEFAULT_KEY_PATH).exists(),
                    'path': str(DEFAULT_KEY_PATH)
                },
                'directories_status': {
                    'config_file_exists': CONFIG_PATH.exists(),
                    'logs_directory_exists': LOGS_DIR.exists(),
                    'vaults_directory_exists': VAULTS_DIR.exists()
                }
            }

            return {
                'success': True,
                'config': enhanced_config,
                'message': "Configuration retrieved successfully"
            }
        except Exception as e:
            self.log.error(f"API get_config error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to get configuration: {str(e)}"
            }

    def update_config(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        """Update system settings"""
        try:
            from obfutil.config import update_language

            updated = []

            # Update language
            if 'language' in settings:
                lang = settings['language']
                if lang in ['en', 'ru', 'de']:
                    update_language(lang)
                    updated.append('language')

            # Can add other settings updates here

            return {
                'success': True,
                'updated_settings': updated,
                'message': f"Updated settings: {', '.join(updated)}" if updated else "No settings updated"
            }
        except Exception as e:
            self.log.error(f"API update_config error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to update configuration: {str(e)}"
            }
    
    def get_system_status(self) -> Dict[str, Any]:
        import sys
        """Get system status and statistics"""
        try:
            from obfutil.config import VERSION
            from pathlib import Path

            # Vault information
            vaults_info = self.list_vaults()
            vaults_count = len(vaults_info.get('vaults', [])) if vaults_info['success'] else 0

            # Key file check
            from obfutil.config import DEFAULT_KEY_PATH
            key_file_exists = Path(DEFAULT_KEY_PATH).exists()

            # Log size
            log_file = Path("logs/program.log")
            logs_size = log_file.stat().st_size if log_file.exists() else 0

            return {
                'success': True,
                'status': {
                    'version': VERSION,
                    'vaults_count': vaults_count,
                    'key_file_exists': key_file_exists,
                    'logs_size_bytes': logs_size,
                    'logs_size_mb': round(logs_size / (1024 * 1024), 2),
                    'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                },
                'message': "System status retrieved successfully"
            }
        except Exception as e:
            self.log.error(f"API get_system_status error: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to get system status: {str(e)}"
            }

    def health_check(self) -> Dict[str, Any]:
        import time
        """Quick system health check"""
        try:
            status = self.get_system_status()

            if status['success']:
                return {
                    'success': True,
                    'status': 'healthy',
                    'timestamp': time.time(),
                    'message': "System is healthy and operational"
                }
            else:
                return {
                    'success': False,
                    'status': 'unhealthy', 
                    'timestamp': time.time(),
                    'message': "System health check failed"
                }
        except Exception as e:
            self.log.error(f"API health_check error: {e}")
            return {
                'success': False,
                'status': 'error',
                'timestamp': time.time(),
                'message': f"Health check failed: {str(e)}"
            }

api = ObfUtilAPI()