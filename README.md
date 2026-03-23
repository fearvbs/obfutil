
# ObfUtil - Advanced File Encryption & Obfuscation Tool

![Version](https://img.shields.io/badge/version-3.4-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Vault Commands](#-vault-commands) • [API](#-python-api) • [Changelog](CHANGELOG.md)

## 📖 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Encryption Commands](#-encryption-commands)
- [Vault Commands](#-vault-commands)
- [Integrity Protection](#-integrity-protection)
- [Code Obfuscation](#-code-obfuscation)
- [Python API](#-python-api)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

| Category | Features |
|----------|----------|
| **Encryption** | AES-256 encryption, Password/Key file support, HMAC integrity verification |
| **Vaults** | Encrypted containers, File organization, Storage statistics, Disk usage by folder |
| **Search** | Pattern matching, Extension search, Size filters, Case sensitivity |
| **Obfuscation** | AST-based obfuscation, Variable renaming, String encryption, Anti-tamper |
| **Batch Operations** | Multi-file encryption, Progress tracking, Speed statistics |
| **Multi-language** | English, Russian, German |
| **Security** | Secure memory cleanup, Brute force protection, Hash verification |

## 📦 Installation

### From GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/fearvbs/obfutil.git
cd obfutil

# Install in development mode
pip install -e .
```

### From PyPI

```bash
pip install obfutil
```

### Verify Installation

```bash
obfutil --help
obfutil vault --help
```

## 🚀 Quick Start

### Basic Encryption

```bash
# Encrypt with password
obfutil encrypt secret.txt --password

# Decrypt and edit
obfutil decrypt secret.txt.enc --password

# View encrypted content
obfutil view secret.txt.enc --password
```

### Vault Operations

```bash
# Create a vault
obfutil vault create mydocs --size 100 --password

# Add files
obfutil vault add mydocs document.pdf --password

# List contents
obfutil vault preview mydocs --password

# Extract file
obfutil vault extract mydocs document.pdf ./output.pdf --password
```

## 🔐 Encryption Commands

### Password-Based Encryption

```bash
# Encrypt
obfutil encrypt file.txt --password

# Decrypt with editing
obfutil decrypt file.txt.enc --password

# View only
obfutil view file.txt.enc --password
```

### Key File Encryption

```bash
# Generate key file
obfutil --gen-key

# Encrypt with key
obfutil encrypt file.txt --key-file

# Decrypt with key
obfutil decrypt file.txt.enc --key-file
```

### Batch Operations

```bash
# Encrypt all text files
obfutil batch-encrypt *.txt --password

# Decrypt all encrypted files
obfutil batch-decrypt *.enc --password
```

## 📁 Vault Commands

Vaults are encrypted containers that store multiple files with unified access control.

### Vault Management

| Command | Description | Example |
|---------|-------------|---------|
| `create` | Create new vault | `obfutil vault create myvault --size 100 --password` |
| `list` | List all vaults | `obfutil vault list` |
| `info` | Vault information | `obfutil vault info myvault --password` |
| `delete` | Securely delete vault | `obfutil vault delete myvault` |

### File Operations

| Command | Description | Example |
|---------|-------------|---------|
| `add` | Add file to vault | `obfutil vault add myvault file.txt --password` |
| `extract` | Extract file from vault | `obfutil vault extract myvault file.txt ./out.txt --password` |
| `remove` | Remove file from vault | `obfutil vault remove myvault file.txt --password` |
| `rename` | Rename file in vault | `obfutil vault rename myvault old.txt new.txt --password` |

### Advanced Commands (New in 3.4)

| Command | Description | Example |
|---------|-------------|---------|
| `stats` | Detailed statistics | `obfutil vault stats myvault --password` |
| `du` | Disk usage by folder | `obfutil vault du myvault --password` |
| `search` | Search files | `obfutil vault search myvault "*.pdf" --password` |
| `preview` | Quick file list | `obfutil vault preview myvault --password` |
| `verify` | Integrity check | `obfutil vault verify myvault --deep --password` |
| `storage` | Storage usage | `obfutil vault storage myvault --password` |

### Add Command Options

```bash
# Add with custom internal path
obfutil vault add myvault file.txt docs/file.txt --password

# Add and delete original (move)
obfutil vault add myvault file.txt --password --move

# Overwrite existing file
obfutil vault add myvault file.txt --password --force
```

### Search Filters

```bash
# Search by pattern
obfutil vault search myvault "*.pdf" --password

# Search by extension
obfutil vault search myvault "jpg" --type ext --password

# Search by substring
obfutil vault search myvault "secret" --type contains --password

# Search with size filters
obfutil vault search myvault "*.mp4" --min-size 10 --max-size 100 --password

# Case-sensitive search
obfutil vault search myvault "README" --case --password
```

### Statistics Output Example

```
=== Vault Statistics: myvault ===
==================================================
Total Files:    47
Total Size:     128.5 MB
Average Size:   2.7 MB

Largest File:   video.mp4 (45.2 MB)
Oldest File:    config.ini (2024-01-15)
Newest File:    report.pdf (2026-03-23)

File Types:
  .pdf    12 files   45.2 MB  ████████████████░░░░░░░░░░░░░░
  .jpg     8 files   32.1 MB  ████████████░░░░░░░░░░░░░░░░░░
  .txt    15 files    0.8 MB  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  .mp4     1 file    45.2 MB  ████████████████░░░░░░░░░░░░░░
```

## 🛡️ Integrity Protection

```bash
# Encrypt with integrity check
obfutil encrypt-int sensitive.doc --password

# Verify file integrity
obfutil verify-int sensitive.doc.enc --password

# Decrypt with integrity verification
obfutil decrypt-int sensitive.doc.enc --password
```

## 🔧 Code Obfuscation

```bash
# Obfuscate Python script
obfutil obfuscate script.py

# Output: script_obf.py
```

Obfuscation features:
- Variable name randomization
- String encryption
- Code shredding
- Anti-tamper protection
- Junk code injection

## 🐍 Python API

```python
from obfutil.core.api import api

# File encryption
result = api.encrypt_file("document.txt", password="secret")
if result['success']:
    print(f"Encrypted: {result['output_path']}")

# Vault operations
api.create_vault("myvault", size_mb=100, password="vaultpass")
api.add_file_to_vault("myvault", "file.txt", password="vaultpass")

# Get statistics
stats = api.get_vault_statistics("myvault", password="vaultpass")
print(f"Files: {stats['total_files']}, Size: {stats['total_size_mb']} MB")

# Search files
files = api.search_files_in_vault("myvault", "*.pdf", password="vaultpass")
for file in files:
    print(f"Found: {file['path']} ({file['size_kb']} KB)")

# Batch operations
result = api.encrypt_files_batch(["file1.txt", "file2.txt"], password="secret")
print(f"Processed: {result['successful']}/{result['processed']} files")
```

## ⚙️ Configuration

All data is stored in `~/.obfutil/`:

```
~/.obfutil/
├── config.ini          # User configuration
├── vaults/             # Encrypted vault files
│   ├── myvault.obfvault
│   └── vaults.json     # Vault registry
├── logs/               # Operation logs
│   └── program.log
└── secret.key          # Encryption key (if generated)
```

### Configuration Commands

```bash
# Show current configuration
obfutil config --show

# Change language
obfutil config --lang ru     # Russian
obfutil config --lang de     # German
obfutil config --lang en     # English

# Generate password
obfutil --gen-pass 16

# Generate key file
obfutil --gen-key
```

## 🖥️ System Requirements

- **Python**: 3.9 or higher
- **Dependencies**: cryptography, astor
- **Platform**: Windows, Linux, macOS
- **Storage**: ~/.obfutil/ directory with write permissions

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🌟 Version 3.4 Highlights

- 📊 **`vault stats`** - Detailed file statistics and type distribution
- 🔍 **`vault search`** - Powerful search with size and type filters
- 📁 **`vault du`** - Disk usage analysis by folder
- ✏️ **`vault rename`** - Rename files inside vaults
- ⚡ **`--force`** - Overwrite existing files
- 🛡️ **Improved hash verification** - Fixed after rename operations
- 🌐 **Better error messages** - Actionable suggestions

---

*For full changelog, see [CHANGELOG.md](CHANGELOG.md)*
