# Changelog

All notable changes to ObfUtil will be documented in this file.

## V1.0
**Added**
- First release of obfuscator with limited usage

## V1.1
**Added**
- .exe executable tool
- Password hiding with "*" characters
- File replacement after encryption
- New console interface

**Changed**
- Almost fully recoded main.py
- Flag-based system instead of options

## V1.2
**Added**
- Raw README.md
- Python script obfuscation
- Double obfuscation with marshal
- Temp file editing with re-encryption

**Changed**
- Single main script architecture

**Fixed**
- Password hiding for Windows and Linux
- Password exception handling
- Interface invalid flags
- Reorganized main.py for cleaner code structure
- Recoded encryption/decryption functions

## V1.3
**Added**
- New UI with usage, commands, options and examples
- Configuration system in main script
- Russian language localization
- Argument parser for options

**Removed**
- requirements.txt

## V1.4
**Added**
- config.ini external configuration
- More usage examples
- -v, --version flag

**Changed**
- Separated config, localization and main files

**Removed**
- German language from selection

## V1.5
**Added**
- 12-character password generation

**Fixed**
- config.ini creation in main script

**Changed**
- Examples format (removed # symbols)

## V2.0-aes256
**Added**
- AES-256 encryption support
- aes.py for Python script obfuscation

**Changed**
- Project to modular structure
- Locales separated into JSON files

**Fixed**
- config.py to properly create config file

**Removed**
- Legacy code

## V2.0-release
**Added**
- Advanced Python obfuscation (import rewriter, self-mod code, CFG, junk code)
- Flexible password generation (>8 symbols)

**Changed**
- Examples to more compact format
- Name from CryptoObfuscator to ObfUtil
- Global reorganization of all code

**Fixed**
- Main function structure

## V2.1
**Added**
- "Nuclear" obfuscation method for Python scripts

## V2.2
**Added**
- Default language recognition
- Logging via .log file
- .gitignore
- Troubleshooting support

**Fixed**
- --lang flag functionality
- --gen-key and --gen-pass commands
- Encryption/decryption/view operations
- UI formatting and version display

**Changed**
- Rebranded as "advanced encryption tool"

## V2.3
**Added**
- HMAC support for tamper detection
- New commands: encrypt-integrity, decrypt-integrity, verify-integrity
- File integrity check system with SHA-256 hashing
- Modular architecture with int_check.py module
- --cmds command for complete usage examples

**Changed**
- Better user experience with compact menu
- Expanded localization with new translations
- Examples located in module examples.py

**Fixed**
- Incomplete error handling in file operations
- Function signature mismatches in main.py

## V3.0-global
**Added**
- Encrypted vault system for secure file containers
- Vault operations: create/list/info/add/extract/remove/delete
- File integrity verification system with HMAC and SHA-256
- --move option for vault file operations
- German language support (Deutsch)
- Real file data storage in vaults with proper offset management
- Hash verification for file integrity checking
- File table management with dynamic offset calculations
- Vault metadata system with creation time and size tracking
- API support framework for future extensions
- Comprehensive README.md documentation
- Password-based and key-file encryption options for vaults
- Automatic duplicate file name handling in vaults
- Exponential backoff for failed vault access attempts
- Vault status tracking (ACTIVE/MISSING/LOCKED)
- Advanced batch operations for multiple files
- System status and configuration management commands
- Structured help system with categorized examples
- Extended batch statistics with file sizes and processing speed
- Vault usage analysis with capacity monitoring
- Enhanced configuration with system environment info
- Batch operations progress tracking and performance metrics
- File type analysis for vault content categorization
- Largest file identification in vault analysis

**Changed**
- Complete CLI interface redesign with cleaner command structure
- Multi-language help system with comprehensive examples
- Improved error messages and user feedback
- New command-style menu layout with proper tabulation
- Status/Config/Vault help now use centered header format
- Examples organized by categories with descriptions
- Enhanced vault storage architecture with better encryption
- Enhanced configuration display with key file status
- Batch operations show detailed size and speed metrics
- Project structure reorganization for better maintainability
- Transition from .exe utility to pip-installable plugin
- Vault container format with optimized data storage
- Logger integration throughout all modules
- Updated version to 3.1 in configuration system

**Fixed**
- File extraction now returns actual file data with integrity checks
- Hash calculation and verification for vault operations
- Language selection across all commands and subcommands
- Argument parsing for complex vault operations
- File offset management in vault container system
- Vault info command authentication and data display
- Used space calculation in KB for better visibility
- Vault list command formatting and information display
- Duplicate import conflicts in main.py
- API reference errors in status and config commands
- Inconsistent menu formatting and alignment issues
- Language switching bugs in vault commands
- Configuration file parsing errors with supported languages
- Batch operation statistics calculation methods

**Removed**
- Placeholder file extraction implementation
- Old vault command format and legacy syntax
- Unused localization entries and deprecated functions
- Unsecure temporary file handling methods

## V3.1
**Added**
- Consistent logger usage replacing print statements for operational messages

**Changed**
- Print statements to logger calls for system messages
- Debug prints to appropriate logger levels (INFO, WARNING, ERROR)
- Function documentation from Russian to English

**Fixed**
- Duplicate _save_config method in VaultManager class
- Redundant derive_hmac_key_from_password function in integrity.py

**Removed**
- Unnecessary debug print statements from encryption operations
- Redundant logging messages that duplicated functionality
- Direct console output for system events in favor of logger
- Excessive file operation logging in vault management
- Duplicate code in password input handling