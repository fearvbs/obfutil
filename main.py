import os
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== Функция для ввода пароля со звёздочками =====
def input_password(prompt="Введите пароль: "):
    """
    Запрашивает пароль, заменяя символы на звёздочки (*).
    Работает на Windows, Linux и macOS.
    """
    import sys
    if sys.platform == "win32":
        import msvcrt
    else:
        import termios, tty

    password = []
    print(prompt, end="", flush=True)

    # Для Windows
    if sys.platform == "win32":
        while True:
            ch = msvcrt.getch().decode("utf-8", errors="ignore")
            if ch == "\r":  # Enter
                break
            elif ch == "\b":  # Backspace
                if password:
                    password.pop()
                    print("\b \b", end="", flush=True)
            else:
                password.append(ch)
                print("*", end="", flush=True)
    
    # Для Linux/macOS
    else:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                ch = sys.stdin.read(1)
                if ch == "\r" or ch == "\n":  # Enter
                    break
                elif ch == "\x7f":  # Backspace (Linux/macOS)
                    if password:
                        password.pop()
                        print("\b \b", end="", flush=True)
                else:
                    password.append(ch)
                    print("*", end="", flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    print()
    return "".join(password)

# ===== Основные функции шифрования/дешифрования =====
def generate_key(password: str, salt: bytes) -> bytes:
    """Генерирует ключ из пароля с использованием PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_content(file_path: str, password: str) -> bool:
    """Шифрует содержимое файла (имя и расширение остаются прежними)"""
    try:
        if not os.path.exists(file_path):
            logger.error("Файл не существует!")
            return False

        # Читаем содержимое
        with open(file_path, "rb") as f:
            content = f.read()

        # Генерируем ключ
        salt = os.urandom(16)
        key = generate_key(password, salt)
        fernet = Fernet(key)

        # Шифруем и сохраняем (соль + зашифрованные данные)
        encrypted = fernet.encrypt(content)

        # Создаем временный файл
        temp_file = f"{file_path}.tmp"
        with open(temp_file, "wb") as f:
            f.write(salt + encrypted)  # Сохраняем соль и зашифрованные данные

        # Заменяем оригинальный файл
        os.replace(temp_file, file_path)
        return True

    except Exception as e:
        logger.error(f"Ошибка при шифровании: {e}")
        return False

def decrypt_content(file_path: str, password: str) -> bytes | None:
    """Дешифрует содержимое файла и возвращает его"""
    try:
        if not os.path.exists(file_path):
            logger.error("Файл не существует!")
            return None

        # Читаем соль и зашифрованные данные
        with open(file_path, "rb") as f:
            salt = f.read(16)  # Первые 16 байт — соль
            encrypted = f.read()  # Остальное — зашифрованные данные

        # Генерируем ключ
        key = generate_key(password, salt)
        fernet = Fernet(key)

        # Дешифруем
        decrypted = fernet.decrypt(encrypted)
        return decrypted

    except Exception as e:
        logger.error(f"Ошибка при дешифровании: {e}")
        return None

# ===== Основной интерфейс =====
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Шифрование/дешифрование содержимого файлов")
    parser.add_argument("file", help="Имя файла")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Зашифровать файл")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Дешифровать файл (показать содержимое)")
    parser.add_argument("--edit", action="store_true", help="Редактировать файл")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("Ошибка: файл не существует!")
        return

    password = input_password("Введите пароль: ")
    if args.encrypt:
        confirm = input_password("Подтвердите пароль: ")
        if password != confirm:
            print("Пароли не совпадают!")
            return
        if encrypt_content(args.file, password):
            print("Файл успешно зашифрован.")
    elif args.decrypt:
        decrypted = decrypt_content(args.file, password)
        if decrypted:
            print("\n--- Дешифрованное содержимое ---")
            print(decrypted.decode("utf-8", errors="replace"))
    elif args.edit:
        decrypted = decrypt_content(args.file, password)
        if decrypted is None:
            return
        # Сохраняем во временный файл для редактирования
        temp_file = f"{args.file}.tmp"
        try:
            with open(temp_file, "wb") as f:
                f.write(decrypted)
            # Открываем редактор (например, Notepad/Vim/Nano)
            editor = "notepad.exe" if os.name == "nt" else "nano"
            os.system(f'{editor} "{temp_file}"')
            # Читаем измененное содержимое
            with open(temp_file, "rb") as f:
                new_content = f.read()
            # Шифруем и сохраняем
            encrypt_content(args.file, password)
            print("Файл успешно отредактирован и зашифрован.")
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    else:
        print("Укажите действие: --encrypt, --decrypt или --edit")

if __name__ == "__main__":
    main()