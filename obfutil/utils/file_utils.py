from pathlib import Path
import sys
import subprocess
import os

def read_file_safe(path, encoding='utf-8'):
    """Safe file reading"""
    try:
        return Path(path).read_text(encoding=encoding)
    except Exception as e:
        raise IOError(f"Cannot read file {path}: {str(e)}")

def write_file_safe(path, content, encoding='utf-8'):
    """Safe file writing"""
    try:
        Path(path).write_text(content, encoding=encoding)
        return True
    except Exception as e:
        raise IOError(f"Cannot write file {path}: {str(e)}")

def open_file_in_editor(file_path):
    """Open file in default editor"""
    try:
        if sys.platform == "win32":
            os.startfile(file_path)
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.run([opener, file_path])
        return True
    except Exception as e:
        raise RuntimeError(f"Cannot open file {file_path}: {str(e)}")