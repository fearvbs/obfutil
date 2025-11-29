import configparser
import os
from pathlib import Path

# Base application directory
APP_DATA_DIR = Path.home() / ".obfutil"
APP_DATA_DIR.mkdir(exist_ok=True)

# Default paths
CONFIG_PATH = APP_DATA_DIR / "config.ini"
DEFAULT_KEY_PATH = APP_DATA_DIR / "secret.key"
LOGS_DIR = APP_DATA_DIR / "logs"
VAULTS_DIR = APP_DATA_DIR / "vaults"

# Create directories
LOGS_DIR.mkdir(exist_ok=True)
VAULTS_DIR.mkdir(exist_ok=True)

# Default values
VERSION = "3.2"
DEFAULT_LANG = "en"
SUPPORTED_LANGUAGES = "en,ru,de"
DEFAULT_ENCRYPTION_METHOD = "password"

def load_config_file():
    """Load or create config file"""
    if not CONFIG_PATH.exists():
        return create_default_config()

    config = configparser.ConfigParser()
    config.read(CONFIG_PATH, encoding="utf-8")

    if "Settings" not in config:
        return create_default_config()

    s = config["Settings"]

    # Add missing fields
    changed = False
    if "version" not in s:
        s["version"] = VERSION
        changed = True
    if "language" not in s:
        s["language"] = DEFAULT_LANG
        changed = True
    if "supported_languages" not in s:
        s["supported_languages"] = SUPPORTED_LANGUAGES
        changed = True
    if "encryption_method" not in s:
        s["encryption_method"] = DEFAULT_ENCRYPTION_METHOD
        changed = True
    if "key_path" not in s:
        s["key_path"] = str(DEFAULT_KEY_PATH)
        changed = True

    if changed:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            config.write(f)

    return config

def load_config():
    """Load configuration"""
    cfg_file = load_config_file()
    s = cfg_file["Settings"]
    return {
        "version": s.get("version", VERSION),
        "language": s.get("language", DEFAULT_LANG),
        "supported_languages": s.get("supported_languages", SUPPORTED_LANGUAGES),
        "encryption_method": s.get("encryption_method", DEFAULT_ENCRYPTION_METHOD),
        "key_path": s.get("key_path", str(DEFAULT_KEY_PATH))
    }

def create_default_config():
    """Create default config"""
    config = configparser.ConfigParser()
    config["Settings"] = {
        "version": VERSION,
        "language": DEFAULT_LANG,
        "supported_languages": SUPPORTED_LANGUAGES,
        "encryption_method": DEFAULT_ENCRYPTION_METHOD,
        "key_path": str(DEFAULT_KEY_PATH)
    }

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        config.write(f)

    return config

def update_language(new_lang: str):
    """Update language in config"""
    from configparser import ConfigParser
    new_lang = new_lang.lower()
    if new_lang not in ("en", "ru", "de"):
        raise ValueError(f"Unsupported language: {new_lang}")

    config = ConfigParser()
    if CONFIG_PATH.exists():
        config.read(CONFIG_PATH, encoding="utf-8")
    else:
        config["Settings"] = {}

    if "Settings" not in config:
        config["Settings"] = {}

    config["Settings"]["language"] = new_lang

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        config.write(f)