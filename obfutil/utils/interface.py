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
            ("obfutil vault info myvault", t(lang, "vault_info"))
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
    """Display system status in status-style format"""
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
    """Display configuration in status-style format"""
    t = localization.get_translation
    
    if not config_data.get('success'):
        print(t(lang, "error"))
        return
        
    config = config_data['config']
    
    print("\n" + " " * 13 + t(lang, "configuration"))
    print("=" * 40)
    print(f"{t(lang, 'current_language')}: {config.get('language', 'N/A')}")
    print(f"{t(lang, 'version_title')}: {config.get('version', 'N/A')}")
    print(f"{t(lang, 'encryption_method')}: {config.get('encryption_method', 'N/A')}")
    print(f"{t(lang, 'key_path_cfg')}: {config.get('key_path', 'N/A')}")
    
    # New info
    key_status = config.get('key_file_status', {})
    key_exists = key_status.get('exists', False)
    print(f"{t(lang, 'key_file_cfg')}: {t(lang, 'exists') if key_exists else t(lang, 'not_found')}")
    if key_exists:
        print(f"{t(lang, 'key_size')}: {key_status.get('size_mb', 0)} MB")
    
    environment = config.get('environment', {})
    print(f"{t(lang, 'cfg_file_cfg')}: {t(lang, 'exists') if environment.get('config_file_exists') else t(lang, 'not_found')}")
    print(f"{t(lang, 'logs_dir')}: {t(lang, 'exists') if environment.get('logs_directory_exists') else t(lang, 'not_found')}")
    print(f"{t(lang, 'vaults_dir')}: {t(lang, 'exists') if environment.get('vaults_directory_exists') else t(lang, 'not_found')}")
    
    print("=" * 40)

def show_vault_help(lang: str = "en"):
    """Display vault help in status-style format"""
    t = localization.get_translation
    
    vault_commands = [
        "vault create <name> [--size MB]",
        "vault list",
        "vault info <name>", 
        "vault analyze <name>",
        "vault delete <name>",
        "vault add <name> <file> [internal_path] [--move]",
        "vault extract <name> <internal_path> [output_path]",
        "vault remove <name> <internal_path>",
        "vault list-files <name>"
    ]
    
    print("\n" + " " * 13 + t(lang, "vault_help_title"))
    print("=" * 40)
    print(t(lang, "vault_help_usage"))
    print()
    for cmd in vault_commands:
        print(f"  {cmd}")
    print()
    print(t(lang, "vault_help_examples"))
    print(f"  {t(lang, 'vault_create_pass')}")
    print(f"  {t(lang, 'vault_list')}")
    print(f"  {t(lang, 'vault_analyze')}")
    print("=" * 40)



def show_batch_stats(batch_data, lang: str = "en"):
    """Display batch operation statistics"""
    t = localization.get_translation
    
    if not batch_data.get('success'):
        print(t(lang, "error"))
        return
        
    print("\n" + " " * 13 + "BATCH STATISTICS")
    print("=" * 40)
    print(f"{t(lang, 'batch_stats_files')}: {batch_data['processed']}")
    print(f"{t(lang, 'batch_stats_successful')}: {batch_data['successful']}")
    print(f"{t(lang, 'batch_stats_failed')}: {batch_data['failed']}")
    print(f"{t(lang, 'batch_stats_total_size')}: {batch_data['total_size_mb']} MB")
    print(f"{t(lang, 'batch_stats_processed_size')}: {batch_data['processed_size_mb']} MB")
    print(f"{t(lang, 'batch_stats_processing_time')}: {batch_data['processing_time_seconds']} {t(lang, 'seconds')}")
    print(f"{t(lang, 'batch_stats_speed')}: {batch_data['average_speed_mb_s']} MB/s")
    print("=" * 40)

def show_vault_analysis(analysis_data, lang: str = "en"):
    """Display vault usage analysis"""
    t = localization.get_translation
    
    if not analysis_data.get('success'):
        print(t(lang, "error"))
        return
        
    analysis = analysis_data['analysis']
    vault_name = analysis_data['vault_name']
    
    print("\n" + " " * 13 + f"VAULT ANALYSIS: {vault_name}")
    print("=" * 40)
    print(f"{t(lang, 'total_files')}: {analysis['total_files']}")
    print(f"{t(lang, 'total_size')}: {analysis['total_size_mb']} MB")
    print(f"{t(lang, 'vault_capacity')}: {analysis['capacity_mb']} MB")
    print(f"{t(lang, 'vault_used_space')}: {analysis['used_space_mb']} MB ({analysis['usage_percentage']}%)")
    print(f"{t(lang, 'vault_free_space')}: {analysis['free_space_mb']} MB")
    
    # Самый большой файл
    largest = analysis.get('largest_file', {})
    if largest:
        print(f"{t(lang, 'vault_largest_file')}: {largest.get('name', '')} ({largest.get('size_mb', 0)} MB)")
    
    # Типы файлов
    file_types = analysis.get('file_types', {})
    if file_types:
        print(f"\n{t(lang, 'vault_file_types')}:")
        for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  .{ext}: {count} files")
    
    print("=" * 40)