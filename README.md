
# ObfUtil - Advanced File Encryption & Obfuscation Tool



![Version](https://img.shields.io/badge/version-3.1-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)


[Features](#-features) • [Installation](#-installation) • [Usage](#-Basic-usage) • [Documentation](#-documentation) • [Changelog](CHANGELOG.md)


### Installation

### From GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/fearvbs/obfutil.git
cd obfutil

# Install in development mode
pip install -e .
```

### Verify Installation

```bash
# Check if obfutil is available
obfutil --help

# Or using module syntax
python -m obfutil.ui.cli.main --help
```

### For End Users

If you just want to use ObfUtil without development:

```bash
# Install directly from GitHub
pip install git+https://github.com/fearvbs/obfutil.git
```

### Dependencies

ObfUtil will automatically install:
- `cryptography` - For AES-256 encryption
- Other required Python standard library modules

---

**Note**: The `-e` flag installs in "editable" mode, allowing you to modify the code while keeping the installation functional.

## ✨ Features

- **Secure Encryption** - AES-256 with password or keyfile protection
- **Advanced Obfuscation** - Multi-layer Python code protection with anti-debugging
- **Encrypted Vaults** - Secure containers for organizing multiple files
- **Integrity Protection** - HMAC verification and tamper detection
- **Multi-Language UI** - Full support for English, Russian, and German
- **Batch Processing** - Encrypt/decrypt multiple files simultaneously
- **System Analytics** - Real-time monitoring and usage statistics
- **Unified Configuration** - All data stored in `~/.obfutil/` directory

## 📖 Documentation

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `encrypt` | Encrypt files | `obfutil encrypt file.txt --password` |
| `decrypt` | Decrypt files | `obfutil decrypt file.enc --key-file` |
| `view` | View encrypted content | `obfutil view file.enc --password` |
| `obfuscate` | Obfuscate Python code | `obfutil obfuscate script.py` |
| `status` | System status | `obfutil status` |
| `config` | Configuration | `obfutil config --show` |

### Vault Security Model
```
[HEADER][ENCRYPTED_METADATA][ENCRYPTED_FILE_TABLE][ENCRYPTED_FILE_DATA]
```
- **Full Container Encryption**: Entire vault is encrypted as a single unit
- **Metadata Protection**: File names and structure are encrypted
- **No Plaintext Leaks**: No sensitive information exposed in container format

### Anti-Brute Force Measures
```python
# Exponential backoff for failed attempts
if self.failed_attempts >= 3:
    wait_time = (2 ** self.failed_attempts)  # 2, 4, 8, 16... seconds
    time.sleep(wait_time)
```

## 🐍 Python API

Integrate ObfUtil directly into your Python applications:

```python
from obfutil.core.api import api

# File encryption
result = api.encrypt_file("document.txt", password="secret")
if result['success']:
    print(f"Encrypted: {result['output_path']}")

# Vault management
vault_info = api.create_vault("project_data", size_mb=200, password="vault_pass")
files_list = api.list_files_in_vault("project_data", password="vault_pass")

# Batch operations
stats = api.encrypt_files_batch(["file1.txt", "file2.doc"], password="secret")
print(f"Processed: {stats['successful']}/{stats['processed']} files")

# Code obfuscation
result = api.obfuscate_python_code("script.py")
```

## 📁 Project Architecture

```
obfutil/
├── core/
│   ├── api.py              # Python API interface
│   └── ...
├── crypto/
│   ├── encryption.py       # AES-256 encryption algorithms
│   ├── integrity.py        # HMAC verification system
│   └── ...
├── obfuscation/
│   └── core.py            # Multi-layer code obfuscation
├── vault/
│   ├── manager.py         # Vault management system
│   ├── container.py       # Vault container logic
│   ├── commands.py        # CLI commands handler
│   └── ...
├── utils/
│   ├── localization.py    # Multi-language support
│   ├── logger.py          # Logging system
│   ├── file_utils.py      # File operations
│   ├── interface.py       # User interface
│   └── ...
├── ui/cli/
│   └── main.py           # Command-line interface
└── config.py             # Configuration management
```
### Basic Usage

```bash
# Encrypt a file with password
obfutil encrypt document.txt --password

# Decrypt and edit file
obfutil decrypt document.txt.enc --password

# Obfuscate Python code
obfutil obfuscate script.py

# Create encrypted vault
obfutil vault create my_vault --size 100 --password
```

### Vault Operations

Vaults are encrypted containers that can store multiple files with unified access control.

```bash
# Create a vault
obfutil vault create my_docs --size 100 --password

# List all existing vaults
obfutil vault list

# Add files to vault
obfutil vault add my_docs document.pdf --password

# Add files to vault with deletion of original file
obfutil vault add my_docs document.pdf --password --move

# List vault contents
obfutil vault files my_docs --password

# Extract files
obfutil vault extract my_docs document.pdf ./extracted.pdf --password

# Basic vault information
obfutil vault info my_docs

# Advanced vault information
obfutil vault info my_docs --password
```

### Advanced Features

**Integrity Protection:**
```bash
# Encrypt with integrity check
obfutil encrypt-int sensitive.doc --password

# Verify file integrity
obfutil verify-int sensitive.doc.enc --password

# Decrypt with integrity verification
obfutil decrypt-int sensitive.doc.enc --password
```

**Batch Processing:**
```bash
# Encrypt all text files
obfutil batch-encrypt *.txt --password

# Decrypt all encrypted files
obfutil batch-decrypt *.enc --key-file
```

**Key Management:**
```bash
# Generate encryption key 
obfutil --gen-key

# Generate strong password
obfutil --gen-pass 16
```

**Multi-language Support:**
```bash
obfutil --lang ru    # Russian
obfutil --lang de    # German
obfutil --lang en    # English
```

## ❓ Troubleshooting

**Common issues:**
- Permission errors: Ensure write access to `~/.obfutil/`
- Installation issues: Try `pip install --upgrade pip`
- Command not found: Verify Python Scripts directory is in PATH

## 🎯 Use Cases

- **Developers**: Protect intellectual property with code obfuscation
- **Business**: Secure sensitive documents and confidential data
- **Individuals**: Personal file encryption and privacy protection
- **Organizations**: Centralized secure storage with access control
- **Teams**: Shared encrypted vaults for project collaboration
## 🔧 System Requirements

- **Python**: 3.9 or higher
- **Platform**: Windows, Linux, macOS
- **Dependencies**: all Dependencies can be found in `requirements.txt`
- **Storage**: ~/.obfutil/ directory with write permissions
## 🆘 Related

- 📚 **Documentation**: Check the `docs/` directory for detailed guides
- 🐛 **Issues**: Report bugs on the [Issue Tracker](https://github.com/fearvbs/obfutil/issues)
- 💬 **Discussions**: Join conversations on our [Discussions](https://github.com/fearvbs/obfutil/discussions) page
- 🔄 **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for version history

---
## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest new features.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

P.S.: I'd love to upload all previous versions of obfUtil but I'm too lazy to do so.
