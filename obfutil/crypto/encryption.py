import os
import sys
import subprocess
from pathlib import Path
import base64
import secrets
import string
import hashlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from obfutil.config import DEFAULT_KEY_PATH, DEFAULT_LANG
from obfutil.crypto.integrity import derive_hmac_key_from_password, FileIntegrity
from obfutil.utils.logger import get_logger
from obfutil.utils.localization import get_translation

log = get_logger("CRYPTO")

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_key_file(key_path: str = DEFAULT_KEY_PATH) -> bytes:
    """Generate encryption key file"""
    key = Fernet.generate_key()
    with open(key_path, 'wb') as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    return key

def encrypt_file_with_integrity(file, password=None, key=None, lang="en"):
    """Encrypt file with integrity protection"""
    try:
        integrity = FileIntegrity()
        
        # Temporary file with integrity data
        temp_file = file + ".temp_integrity"
        
        # Add integrity data
        hmac_key = None
        if password:
            hmac_key, salt = derive_hmac_key_from_password(password)
        
        integrity_data = integrity.add_integrity_to_file(file, temp_file, hmac_key)
        
        # Encrypt temporary file with standard algorithm
        data = Path(temp_file).read_bytes()
        
        if key:
            enc = encrypt_data(data, key=key)
        else:
            enc = encrypt_data(data, password=password)
            
        out = file + ".enc"
        Path(out).write_bytes(enc)
        
        # Delete temporary file
        os.remove(temp_file)
        
        log.info(f"File encrypted with integrity protection: {out}")
        return integrity_data
        
    except Exception as e:
        log.error(f"Encryption error: {str(e)}")
        return None
    
def generate_password(n=12):
    """Generate random password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*(){}[]_+-="
    return ''.join(secrets.choice(chars) for _ in range(n))

def input_password(prompt):
    """Secure password input with asterisks"""
    try:
        # Windows implementation with asterisks
        if sys.platform == "win32":
            return _windows_password_input(prompt)
        else:
            # Unix uses standard getpass
            return getpass.getpass(prompt)
    except Exception as e:
        # Fallback to regular input
        log.warning(f"Password input failed, using fallback: {e}")
        return input(prompt + " (visible): ")

def _windows_password_input(prompt):
    """Windows password input with asterisks"""
    import msvcrt
    print(prompt, end='', flush=True)
    password_chars = []
    
    while True:
        ch = msvcrt.getch()
        
        # Enter - finish input
        if ch in [b'\r', b'\n']:
            print()
            break
            
        # Backspace - remove character
        elif ch == b'\x08':
            if password_chars:
                password_chars.pop()
                print('\b \b', end='', flush=True)
                
        # Regular character - add and show asterisk
        else:
            try:
                char = ch.decode('utf-8')
                password_chars.append(char)
                print('*', end='', flush=True)
            except UnicodeDecodeError:
                pass
                
    return ''.join(password_chars)

def verify_file_integrity(file, password=None, key=None, lang="en"):
    """Verify encrypted file integrity"""
    try:
        # First decrypt
        data = Path(file).read_bytes()
        
        if key:
            dec_data = decrypt_data(data, key=key)
        elif password:
            dec_data = decrypt_data(data, password=password)
        else:
            log.error("Specify --password or --key-file for verification")
            return
        
        # Save temporary decrypted data
        temp_file = file + ".temp_verify"
        Path(temp_file).write_bytes(dec_data)
        
        # Verify integrity
        integrity = FileIntegrity()
        hmac_key = None
        if password:
            hmac_key, _ = derive_hmac_key_from_password(password)
        
        is_valid, message, original_data = integrity.verify_file_integrity(temp_file, hmac_key)
        
        # Delete temporary file
        os.remove(temp_file)
        
        if is_valid:
            log.info("File integrity verified successfully")
            log.info(f"File size: {len(original_data)} bytes, Hash: {hashlib.sha256(original_data).hexdigest()[:16]}...")
        else:
            log.warning(f"Integrity check failed: {message}")
            
    except Exception as e:
        log.error(f"Verification error: {str(e)}")

def decrypt_file_with_integrity(file, password=None, key=None, edit_mode=False, lang="en"):
    """Decrypt file with integrity verification"""
    try:
        # First decrypt
        data = Path(file).read_bytes()
        
        if key:
            dec_data = decrypt_data(data, key=key)
        elif password:
            dec_data = decrypt_data(data, password=password)
        else:
            log.error("Specify --password or --key-file")
            return
        
        # Save temporary decrypted data
        temp_file = file + ".temp_decrypt"
        Path(temp_file).write_bytes(dec_data)
        
        # Verify integrity
        integrity = FileIntegrity()
        hmac_key = None
        if password:
            hmac_key, _ = derive_hmac_key_from_password(password)
        
        is_valid, message, original_data = integrity.verify_file_integrity(temp_file, hmac_key)
        
        if not is_valid:
            log.warning(f"Integrity check failed: {message}")
            os.remove(temp_file)
            return
        
        # Delete temporary file
        os.remove(temp_file)
        
        if edit_mode:
            # Editing mode
            p = Path(file)
            tmp_edit = p.stem + "_edit" + (p.suffix.replace(".enc", "") or ".txt")
            Path(tmp_edit).write_bytes(original_data)
            
            log.info(f"Editing file: {tmp_edit}")
            
            if sys.platform == "win32":
                os.startfile(tmp_edit)
            else:
                opener = "open" if sys.platform == "darwin" else "xdg-open"
                subprocess.run([opener, tmp_edit])
            
            input("Press Enter after editing to re-encrypt...")
            
            # Read temporary file
            new_data = Path(tmp_edit).read_bytes()
            
            # Re-encrypt
            encrypt_file_with_integrity(tmp_edit, password=password, key=key, lang=lang)
            
            # Delete temporary file
            os.remove(tmp_edit)
            
            log.info("File re-encrypted with integrity protection")
            
        else:
            # Just print data
            print(original_data.decode(errors='replace'))
        
    except Exception as e:
        log.error(f"Decryption error: {str(e)}")

def load_key_from_file(key_path: str = DEFAULT_KEY_PATH) -> bytes:
    """Load key from file"""
    if not Path(key_path).exists():
        raise FileNotFoundError(f"Key file not found: {key_path}")
    with open(key_path, 'rb') as f:
        return f.read()

def encrypt_data(data: bytes, password=None, key=None) -> bytes:
    """Encrypt data"""
    if key:
        return Fernet(key).encrypt(data)
    else:
        salt = os.urandom(16)
        derived_key = generate_key(password, salt)
        return salt + Fernet(derived_key).encrypt(data)

def decrypt_data(data: bytes, password=None, key=None) -> bytes:
    """Decrypt data"""
    if key:
        return Fernet(key).decrypt(data)
    else:
        salt = data[:16]
        enc = data[16:]
        derived_key = generate_key(password, salt)
        return Fernet(derived_key).decrypt(enc)

def encrypt_file(file, password=None, key=None, lang=DEFAULT_LANG):
    """Encrypt file"""
    try:
        data = Path(file).read_bytes()
        enc = encrypt_data(data, password, key)
        out = file + ".enc"
        Path(out).write_bytes(enc)
        log.info(f"File encrypted: {out}")
    except Exception as e:
        log.error(f"Encrypt error: {str(e)}")

def decrypt_file(file, password=None, key=None, edit_mode=False, lang=DEFAULT_LANG):
    """Decrypt file"""
    try:
        data = Path(file).read_bytes()
        dec = decrypt_data(data, password, key)

        if not edit_mode:
            print(dec.decode(errors="replace"))
            return

        p = Path(file)
        tmp = p.stem + "_tmp" + (p.suffix.replace(".enc", "") or ".txt")
        Path(tmp).write_bytes(dec)

        if sys.platform == "win32":
            os.startfile(tmp)
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.run([opener, tmp])

        log.info(f"Editing file: {tmp}")
        input("Press Enter after editing to re-encrypt...")

        new_data = Path(tmp).read_bytes()
        enc2 = encrypt_data(new_data, password, key)

        out = p.stem.replace(".enc", "") + ".enc"
        Path(out).write_bytes(enc2)
        os.remove(tmp)

        log.info("File re-encrypted successfully")

    except Exception as e:
        log.error(f"Decryption error: {str(e)}")
    
def view_file(file, password=None, key=None, lang=DEFAULT_LANG):
    """View file content"""
    try:
        data = Path(file).read_bytes()
        dec = decrypt_data(data, password, key)
        print(dec.decode(errors="replace"))
    except Exception as e:
        log.error(f"View error: {str(e)}")