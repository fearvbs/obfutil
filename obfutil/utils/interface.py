"""
User Interface Module - Handles all UI output
Version 3.4: Updated with new vault commands:
- search, rename, du, stats
- Improved help formatting
"""

import obfutil.utils.localization as localization
from obfutil.config import VERSION


def show_menu(lang: str = "en"):
    """Display main menu in command-style format"""
    t = localization.get_translation
    
    print(f"\n{t(lang, 'usage')}")
    print("  obfUtil <command> <file> [options]")
    print()
    print(f"{t(lang, 'commands')}")
    commands = [
        ("encrypt", t(lang, "encrypt_cmd")),
        ("decrypt", t(lang, "decrypt_cmd")),
        ("view", t(lang, "view_cmd")),
        ("obfuscate", t(lang, "obfuscate_cmd")),
        ("encrypt-int", t(lang, "encrypt_int_cmd")),
        ("verify-int", t(lang, "verify_int_cmd")),
        ("vault", t(lang, "vault_cmd") + " (obfutil vault --help)"),
        ("status", t(lang, "status_cmd")),
        ("config", t(lang, "config_cmd"))
    ]
    for cmd, desc in commands:
        print(f"    {cmd:<30} {desc}")
    
    print()
    print(f"{t(lang, 'options')}")
    options = [
        ("--password", t(lang, "use_pass_enc")),
        ("--key-file", t(lang, "key_file_enc")),
        ("--gen-key", t(lang, "gen_key")),
        ("--gen-pass <n>", t(lang, "gen_pass")),
        ("--lang <en/ru/de>", t(lang, "lang_opt_desc")),
        ("--help, -h", t(lang, "help_opt")),
        ("--cmds", t(lang, "show_examples_cmd"))
    ]
    for opt, desc in options:
        print(f"    {opt:<30} {desc}")
    
    print()
    print(f"{t(lang, 'examples')}")
    examples = [
        ("Encryption:", f"obfUtil encrypt file.ext --password / --key-file"),
        ("Decryption:", f"obfUtil decrypt file.ext.enc --password / --key-file"),
        ("View:", f"obfUtil view file.ext.enc --password / --key-file"),
        ("Vault:", f"obfUtil vault create name --size MB --password"),
        ("obfutil status", t(lang, "status_example")),
        ("obfutil config --show", t(lang, "config_show_example"))
    ]
    for label, example in examples:
        print(f"    {label:<30} {example}")


def show_example_cmds(lang: str = "en"):
    """Show complete usage examples"""
    t = localization.get_translation
    
    print(t(lang, "examples_title"))
    
    sections = [
        (t(lang, "password_generation"), [
            ("obfutil --gen-pass 12", t(lang, "gen_pass_12"))
        ]),
        (t(lang, "key_management"), [
            ("obfutil --gen-key", t(lang, "gen_key_example"))
        ]),
        (t(lang, "obfuscation"), [
            ("obfutil obfuscate script.py", t(lang, "obfuscate_simple"))
        ]),
        (t(lang, "encryption_password"), [
            ("obfutil encrypt file.txt --password", t(lang, "encrypt_pass_file")),
            ("obfutil encrypt-int data.doc --password", t(lang, "encrypt_integrity_pass"))
        ]),
        (t(lang, "encryption_keyfile"), [
            ("obfutil encrypt file.txt --key-file", t(lang, "encrypt_key_file")),
            ("obfutil encrypt-int data.doc --key-file", t(lang, "encrypt_integrity_key"))
        ]),
        (t(lang, "integrity_operations"), [
            ("obfutil verify-int file.enc --password", t(lang, "verify_integrity_pass"))
        ]),
        (t(lang, "vault_operations"), [
            ("obfutil vault create myvault --size 100 --password", t(lang, "vault_create_pass")),
            ("obfutil vault create bigvault --size 500 --key-file", t(lang, "vault_create_key")),
            ("obfutil vault list", t(lang, "vault_list")),
            ("obfutil vault info myvault", t(lang, "vault_info")),
            ("obfutil vault stats myvault --password", "Show detailed statistics"),
            ("obfutil vault du myvault --password", "Show disk usage by folder"),
            ("obfutil vault search myvault \"*.pdf\" --password", "Search files by pattern"),
            ("obfutil vault rename myvault old.txt new.txt --password", "Rename files"),
            ("obfutil vault add myvault file.txt --password --force", "Add with overwrite")
        ]),
        (t(lang, "decryption_viewing"), [
            ("obfutil decrypt file.enc --password", t(lang, "decrypt_edit_pass")),
            ("obfutil view file.enc --key-file", t(lang, "view_only_key")),
            ("obfutil decrypt-int file.enc --password", t(lang, "decrypt_integrity_pass"))
        ]),
        (t(lang, "system_operations"), [
            ("obfutil status", t(lang, "status_example")),
            ("obfutil config --show", t(lang, "config_show_example")),
            ("obfutil config --lang ru", t(lang, "config_example"))
        ]),
        (t(lang, "batch_operations"), [
            ("obfutil batch-encrypt *.txt --password", t(lang, "batch_encrypt_example")),
            ("obfutil batch-decrypt *.enc --key-file", t(lang, "batch_decrypt_example"))
        ])
    ]
    
    for section_title, commands in sections:
        print(f"\n{section_title}")
        for cmd, desc in commands:
            print(f"    {cmd:<45} {desc}")


def show_system_status(status_data, lang: str = "en"):
    """Display system status"""
    t = localization.get_translation
    
    if not status_data.get('success'):
        print(t(lang, "error"))
        return
        
    status = status_data['status']
    
    print("\n" + " " * 13 + t(lang, "system_status"))
    print("=" * 40)
    print(f"Version: {status.get('version', 'N/A')}")
    print(f"Python Version: {status.get('python_version', 'N/A')}")
    print(f"Vaults Count: {status.get('vaults_count', 'N/A')}")
    print(f"Key File: {'Exists' if status.get('key_file_exists') else 'Not found'}")
    print(f"Logs Size: {status.get('logs_size_mb', 'N/A')} MB")
    print("=" * 40)


def show_configuration(config_data, lang: str = "en"):
    """Display configuration with proper paths"""
    t = localization.get_translation
    
    if not config_data.get('success'):
        print(t(lang, "error"))
        return
        
    config = config_data['config']
    
    print("\n" + " " * 13 + t(lang, "configuration"))
    print("=" * 50)
    print(f"{t(lang, 'current_language')}: {config.get('language', 'N/A')}")
    print(f"{t(lang, 'version_title')}: {config.get('version', 'N/A')}")
    print(f"{t(lang, 'encryption_method')}: {config.get('encryption_method', 'N/A')}")
    
    # Show paths
    if 'paths' in config:
        paths = config['paths']
        print(f"\n{t(lang, 'paths')}:")
        print(f"  Config: {paths.get('config_file', 'N/A')}")
        print(f"  Key File: {paths.get('key_file', 'N/A')}")
        print(f"  Logs: {paths.get('logs_directory', 'N/A')}")
        print(f"  Vaults: {paths.get('vaults_directory', 'N/A')}")
        print(f"  App Data: {paths.get('app_data_directory', 'N/A')}")
    
    # Show status
    if 'directories_status' in config:
        status = config['directories_status']
        print(f"\n{t(lang, 'status')}:")
        status_icon = 'OK' if status.get('config_file_exists') else 'X'
        print(f"  Config file: {status_icon} {t(lang, 'exists') if status.get('config_file_exists') else t(lang, 'not_found')}")
        status_icon = 'OK' if status.get('logs_directory_exists') else 'X'
        print(f"  Logs directory: {status_icon} {t(lang, 'exists') if status.get('logs_directory_exists') else t(lang, 'not_found')}")
        status_icon = 'OK' if status.get('vaults_directory_exists') else 'X'
        print(f"  Vaults directory: {status_icon} {t(lang, 'exists') if status.get('vaults_directory_exists') else t(lang, 'not_found')}")
    
    print("=" * 50)


def show_vault_help(lang: str = "en"):
    """Display vault help with V3.4 features"""
    t = localization.get_translation
    
    vault_commands = [
        ("create", "vault create <name> [--size MB]", "Create a new encrypted vault"),
        ("list", "vault list", "List all existing vaults"),
        ("info", "vault info <name>", "Show detailed vault information"),
        ("preview", "vault preview <name>", "Show files and metadata (quick view)"),
        ("stats", "vault stats <name>", "Show detailed vault statistics"),
        ("du", "vault du <name>", "Show disk usage by folder"),
        ("search", "vault search <name> <pattern> [--type name|ext|contains] [--min-size MB] [--max-size MB]", "Search files by pattern"),
        ("rename", "vault rename <name> <old> <new>", "Rename a file inside vault"),
        ("verify", "vault verify <name> [--deep]", "Verify vault integrity"),
        ("storage", "vault storage <name>", "Show storage usage"),
        ("add", "vault add <name> <file> [internal_path] [--move] [--force]", "Add file to vault"),
        ("extract", "vault extract <name> <internal_path> <output_path>", "Extract file from vault"),
        ("remove", "vault remove <name> <internal_path>", "Remove file from vault"),
        ("delete", "vault delete <name>", "Securely delete entire vault")
    ]
    
    print("\n" + " " * 13 + "OBFUTIL VAULT - ENCRYPTED FILE CONTAINERS")
    print("=" * 65)
    print("Usage: obfutil vault <command> [options]")
    print()
    print("COMMANDS:")
    print("-" * 65)
    
    for cmd_name, cmd_syntax, cmd_desc in vault_commands:
        # Split syntax for better formatting
        print(f"  {cmd_syntax}")
        print(f"      {cmd_desc}")
        print()
    
    print("AUTHENTICATION:")
    print("-" * 65)
    print("  --password              Use password encryption (will prompt)")
    print("  --key-file              Use key file encryption (requires --gen-key first)")
    print()
    
    print("EXAMPLES:")
    print("-" * 65)
    print("  # Create a 100MB vault with password")
    print("  obfutil vault create myvault --size 100 --password")
    print()
    print("  # Add a file (with overwrite if exists)")
    print("  obfutil vault add myvault document.pdf --password --force")
    print()
    print("  # Search for PDF files larger than 1MB")
    print("  obfutil vault search myvault \"*.pdf\" --min-size 1 --password")
    print()
    print("  # Show detailed statistics")
    print("  obfutil vault stats myvault --password")
    print()
    print("  # Check disk usage by folder")
    print("  obfutil vault du myvault --password")
    print()
    print("  # Verify integrity with deep check")
    print("  obfutil vault verify myvault --deep --password")
    print()
    print("  # Securely delete vault")
    print("  obfutil vault delete myvault")
    print("=" * 65)


def show_batch_stats(batch_data, lang: str = "en"):
    """Display batch operation statistics"""
    t = localization.get_translation
    
    if not batch_data.get('success'):
        print(t(lang, "error"))
        return
        
    print("\n" + " " * 13 + "BATCH STATISTICS")
    print("=" * 50)
    print(f"{t(lang, 'batch_stats_files')}: {batch_data['processed']}")
    print(f"{t(lang, 'batch_stats_successful')}: {batch_data['successful']}")
    print(f"{t(lang, 'batch_stats_failed')}: {batch_data['failed']}")
    print(f"{t(lang, 'batch_stats_total_size')}: {batch_data['total_size_mb']} MB")
    print(f"{t(lang, 'batch_stats_processed_size')}: {batch_data['processed_size_mb']} MB")
    print(f"{t(lang, 'batch_stats_processing_time')}: {batch_data['processing_time_seconds']} {t(lang, 'seconds')}")
    print(f"{t(lang, 'batch_stats_speed')}: {batch_data['average_speed_mb_s']} MB/s")
    print("=" * 50)


def show_vault_analysis(analysis_data, lang: str = "en"):
    """Display vault usage analysis"""
    t = localization.get_translation
    
    if not analysis_data.get('success'):
        print(t(lang, "error"))
        return
        
    analysis = analysis_data['analysis']
    vault_name = analysis_data['vault_name']
    
    print("\n" + " " * 13 + f"VAULT ANALYSIS: {vault_name}")
    print("=" * 55)
    print(f"{t(lang, 'total_files')}: {analysis['total_files']}")
    print(f"{t(lang, 'total_size')}: {analysis['total_size_mb']} MB")
    print(f"{t(lang, 'vault_capacity')}: {analysis['capacity_mb']} MB")
    print(f"{t(lang, 'vault_used_space')}: {analysis['used_space_mb']} MB ({analysis['usage_percentage']}%)")
    print(f"{t(lang, 'vault_free_space')}: {analysis['free_space_mb']} MB")
    
    # Largest file
    largest = analysis.get('largest_file', {})
    if largest:
        print(f"{t(lang, 'vault_largest_file')}: {largest.get('name', '')} ({largest.get('size_mb', 0)} MB)")
    
    # File types
    file_types = analysis.get('file_types', {})
    if file_types:
        print(f"\n{t(lang, 'vault_file_types')}:")
        for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  .{ext}: {count} files")
    
    print("=" * 55)