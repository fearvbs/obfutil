import random
import zlib
import base64
import marshal
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ===== Улучшенная функция ввода пароля =====
def input_password(prompt="Введите пароль: "):
    """Кросс-платформенный ввод пароля со звёздочками"""
    if sys.platform == "win32":
        import msvcrt
        password = []
        print(prompt, end='', flush=True)
        while True:
            ch = msvcrt.getwch()  # Для Windows
            if ch == '\r':
                break
            elif ch == '\b':
                if password:
                    password.pop()
                    print('\b \b', end='', flush=True)
            else:
                password.append(ch)
                print('*', end='', flush=True)
        print()
        return ''.join(password)
    else:
        try:
            from getpass import getpass
            return getpass(prompt)
        except ImportError:
            print("Внимание: пароль будет виден при вводе!")
            return input(prompt)

# ===== Основные функции шифрования =====
def generate_key(password: str, salt: bytes) -> bytes:
    """Генерирует ключ из пароля"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: bytes, password: str) -> bytes:
    """Шифрует данные с паролем"""
    salt = os.urandom(16)
    key = generate_key(password, salt)
    f = Fernet(key)
    return salt + f.encrypt(data)

def decrypt_data(encrypted: bytes, password: str) -> bytes:
    """Дешифрует данные с паролем"""
    salt, encrypted = encrypted[:16], encrypted[16:]
    key = generate_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted)

# ===== Функции обфускации =====
def random_name(length=8):
    """Генерирует случайное имя переменной"""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
    return ''.join(random.choice(chars) for _ in range(length))

def obfuscate_code(source_code: str) -> str:
    """Обфусцирует исходный код"""
    compressed = zlib.compress(source_code.encode())
    encoded = base64.b64encode(compressed).decode('utf-8')
    var_names = [random_name() for _ in range(4)]
    
    return f"""
import zlib, base64
{var_names[0]} = b"{encoded}"
{var_names[1]} = base64.b64decode({var_names[0]})
{var_names[2]} = zlib.decompress({var_names[1]})
exec({var_names[2]}.decode('utf-8'))


def deep_obfuscate(code: str) -> bytes:
    """Двойная обфускация с marshal"""
    obfuscated = obfuscate_code(code)
    compiled = compile(obfuscated, '<string>', 'exec')
    return marshal.dumps(compiled)

# ===== Основные операции =====
def encrypt_file(input_path: str, password: str):
    """Шифрует файл с обфускацией"""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        obfuscated = deep_obfuscate(code)
        encrypted = encrypt_data(obfuscated, password)
        
        output_path = input_path + '.enc'
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        
        print(f"Файл зашифрован: {output_path}")
        return True
    
    except Exception as e:
        print(f"Ошибка шифрования: {e}")
        return False

def decrypt_file(input_path: str, password: str, edit_mode=False):
    """Дешифрует файл"""
    try:
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        
        decrypted = decrypt_data(encrypted, password)
        code_obj = marshal.loads(decrypted)
        
        if edit_mode:
            temp_file = input_path.replace('.enc', '.tmp.py')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write("# Редактируйте этот файл\n")
                exec(code_obj, {'__file__': temp_file})
            
            print(f"Файл для редактирования: {temp_file}")
            input("Нажмите Enter после редактирования...")
            
            with open(temp_file, 'r', encoding='utf-8') as f:
                new_code = f.read()
            
            new_obfuscated = deep_obfuscate(new_code)
            new_encrypted = encrypt_data(new_obfuscated, password)
            
            with open(input_path, 'wb') as f:
                f.write(new_encrypted)
            
            os.remove(temp_file)
            print("Файл перешифрован.")
            return True
        else:
            exec(code_obj)
            return True
    
    except Exception as e:
        print(f"Ошибка дешифрования: {e}")
        return False

# ===== Интерфейс командной строки =====
def main():
    if len(sys.argv) < 3:
        print("Использование:")
        print("  Шифрование: python script.py encrypt file.py")
        print("  Просмотр:   python script.py view file.enc")
        print("  Редактирование: python script.py edit file.enc")
        return

    mode = sys.argv[1]
    file_path = sys.argv[2]

    if mode == 'encrypt':
        password = input_password("Введите пароль для шифрования: ")
        confirm = input_password("Подтвердите пароль: ")
        if password == confirm:
            encrypt_file(file_path, password)
        else:
            print("Пароли не совпадают!")
    elif mode == 'view':
        password = input_password("Введите пароль: ")
        decrypt_file(file_path, password)
    elif mode == 'edit':
        password = input_password("Введите пароль: ")
        decrypt_file(file_path, password, edit_mode=True)
    else:
        print("Неизвестная команда. Используйте encrypt/view/edit")

if __name__ == "__main__":
    main()
