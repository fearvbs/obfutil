import hashlib
import hmac
import os
import json
from typing import Tuple, Optional, Dict
from pathlib import Path

class IntegrityChecker:
    def __init__(self, algorithm: str = 'sha256'):
        self.algorithm = algorithm
    
    def compute_hash(self, data: bytes) -> str:
        """Compute data hash"""
        return hashlib.new(self.algorithm, data).hexdigest()
    
    def compute_hmac(self, data: bytes, key: bytes) -> str:
        """Compute HMAC for data with key"""
        return hmac.new(key, data, self.algorithm).hexdigest()
    
    def generate_integrity_data(self, data: bytes, hmac_key: Optional[bytes] = None) -> Dict:
        """Generate integrity verification data"""
        integrity_data = {
            'hash': self.compute_hash(data),
            'size': len(data),
            'algorithm': self.algorithm
        }
        
        if hmac_key:
            integrity_data['hmac'] = self.compute_hmac(data, hmac_key)
        
        return integrity_data
    
    def verify_integrity(self, data: bytes, expected_hash: str, 
                        expected_hmac: Optional[str] = None, 
                        hmac_key: Optional[bytes] = None) -> Tuple[bool, str]:
        """Verify data integrity"""
        try:
            # Check size
            if len(data) == 0:
                return False, "Empty data"
            
            # Check hash
            actual_hash = self.compute_hash(data)
            if actual_hash != expected_hash:
                return False, f"Hash mismatch"
            
            # Check HMAC (if required)
            if expected_hmac and hmac_key:
                actual_hmac = self.compute_hmac(data, hmac_key)
                if not hmac.compare_digest(actual_hmac, expected_hmac):
                    return False, f"HMAC mismatch"
            
            return True, "Integrity verified successfully"
            
        except Exception as e:
            return False, f"Integrity check error: {str(e)}"


class FileIntegrity:
    def __init__(self):
        self.checker = IntegrityChecker()
    
    def add_integrity_to_file(self, input_file: str, output_file: str, 
                            hmac_key: Optional[bytes] = None) -> Dict:
        """Add integrity data to file"""
        try:
            # Read source data
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Generate integrity data
            integrity_data = self.checker.generate_integrity_data(data, hmac_key)
            
            # File format: [INTEGRITY_JSON_LENGTH(4 bytes)][JSON_DATA][ORIGINAL_DATA]
            json_data = json.dumps(integrity_data).encode('utf-8')
            json_length = len(json_data)
            
            # Write to new file
            with open(output_file, 'wb') as f:
                f.write(json_length.to_bytes(4, 'big'))  # JSON length
                f.write(json_data)                       # JSON data
                f.write(data)                           # Source data
            
            return integrity_data
            
        except Exception as e:
            raise Exception(f"Failed to add integrity data: {str(e)}")
    
    def verify_file_integrity(self, file_path: str, 
                            hmac_key: Optional[bytes] = None) -> Tuple[bool, str, bytes]:
        """Verify file integrity with integrity data"""
        try:
            with open(file_path, 'rb') as f:
                # Read JSON data length
                json_length_bytes = f.read(4)
                if len(json_length_bytes) < 4:
                    return False, "Invalid file format", b""
                
                json_length = int.from_bytes(json_length_bytes, 'big')
                
                # Read JSON data
                json_data = f.read(json_length)
                if len(json_data) < json_length:
                    return False, "Corrupted integrity data", b""
                
                # Read source data
                file_data = f.read()
            
            # Parse JSON
            integrity_info = json.loads(json_data.decode('utf-8'))
            
            # Verify integrity
            is_valid, message = self.checker.verify_integrity(
                file_data, 
                integrity_info['hash'],
                integrity_info.get('hmac'),
                hmac_key
            )
            
            return is_valid, message, file_data
            
        except Exception as e:
            return False, f"Verification failed: {str(e)}", b""
    
    def extract_original_data(self, input_file: str, output_file: str, 
                            hmac_key: Optional[bytes] = None) -> bool:
        """Extract source data from file with integrity verification"""
        is_valid, message, data = self.verify_file_integrity(input_file, hmac_key)
        
        if is_valid:
            with open(output_file, 'wb') as f:
                f.write(data)
            return True
        else:
            return False


# HMAC key utilities
def generate_hmac_key() -> bytes:
    """Generate random HMAC key"""
    return os.urandom(16)

def derive_hmac_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Derive HMAC key from password with fixed salt"""
    if salt is None:
        salt = hashlib.sha256(password.encode()).digest()[:16]
    
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key, salt