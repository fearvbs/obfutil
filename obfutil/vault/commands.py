from pathlib import Path

from obfutil.vault.manager import VaultManager
from obfutil.crypto.encryption import input_password, load_key_from_file
from obfutil.config import DEFAULT_KEY_PATH
from obfutil.utils.localization import get_translation
from obfutil.utils.logger import get_logger
from obfutil.utils.interface import show_vault_help

def handle_vault_command(args, lang):
    """Handle vault commands"""
    logger = get_logger("VAULT_CLI")
    
    try:
        # If command is --help or no subcommand, show help
        if not args.vault_command or args.vault_command in ['help', '--help', '-h']:
            show_vault_help(lang)
            return
            
        manager = VaultManager()
        logger.info(f"Processing vault command: {args.vault_command}")
        
        if args.vault_command == 'create':
            if not args.vault_name or args.vault_name in ['--help', '-h', 'help']:
                print("Usage: obfutil vault create <vault_name> --size <MB> --password [--key-file]")
                print("Example: obfutil vault create my_vault --size 100 --password")
                return
                
            password = None
            key = None
            
            if args.key_file:
                try:
                    key = load_key_from_file(DEFAULT_KEY_PATH)
                    logger.debug("Using key file for vault creation")
                except FileNotFoundError:
                    logger.error(f"Key file not found: {DEFAULT_KEY_PATH}")
                    print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
                    print("Generate a key first with: obfutil --gen-key")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
                logger.debug("Using password for vault creation")
            else:
                logger.error("No encryption method specified for vault creation")
                print("ERROR: Specify --password or --key-file for encryption")
                return
            
            size = args.size or 100  # default size
            if size < 1 or size > 1024:
                logger.error(f"Invalid vault size: {size}MB")
                print("ERROR: Size must be between 1MB and 1024MB")
                return
                
            success = manager.create_vault(args.vault_name, size, password, key)
        
        elif args.vault_command == 'list':
            logger.debug("Listing all vaults")
            vaults = manager.list_vaults()
            if not vaults:
                logger.info("No vaults found")
                print("No vaults found.")
                print("Create a vault with: obfutil vault create <name> --size <MB> --password")
                return

            logger.info(f"Displaying {len(vaults)} vault(s)")
            print("\n=== Your Vaults ===")
            print("-" * 50)
            print(f"{'Status':<8} {'Name':<15} {'Size':<10} {'Created':<12}")
            print("-" * 50)

            for vault in vaults:
                status = vault.get('status', 'UNKNOWN')
                name = vault['name']
                size = f"{vault.get('total_size_mb', 0)}MB"
                created = vault.get('created_at', 'Unknown')[:10]  # Date only

                print(f"{status:<8} {name:<15} {size:<10} {created:<12}")

            print(f"\nTotal: {len(vaults)} vault(s)")
            print("\nUse 'obfutil vault info <name> --password' for detailed file information")

        elif args.vault_command == 'info':
            if not args.vault_name:
                logger.error("Vault name not provided for info command")
                print("ERROR: Vault name required")
                return

            logger.info(f"Getting info for vault: {args.vault_name}")

            # Check if vault exists
            exists = manager.vault_exists(args.vault_name)
            logger.info(f"Vault exists check result: {exists}")

            if not exists:
                logger.warning(f"Vault not found: {args.vault_name}")
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                print("Available vaults:")
                vaults = manager.list_vaults()
                for vault in vaults:
                    status = vault.get('status', 'UNKNOWN')
                    print(f"  {status} {vault['name']}")
                return

            # Request password for detailed information
            password = None
            key = None

            if args.password:
                password = input_password(get_translation(lang, "password_prompt"))
            elif args.key_file:
                try:
                    key = load_key_from_file(DEFAULT_KEY_PATH)
                except FileNotFoundError:
                    print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
                    return

            info = manager.get_vault_info(args.vault_name, password, key)
            if not info:
                logger.error(f"Could not read vault info for: {args.vault_name}")
                print(f"ERROR: Could not read vault info for '{args.vault_name}'")
                return

            logger.info(f"Displaying info for vault: {args.vault_name}")
            print(f"\n=== Vault Info: {args.vault_name} ===")
            print("=" * 50)
            print(f"  Path:        {info['path']}")
            print(f"  Status:      {info.get('status', 'UNKNOWN')}")
            print(f"  Created:     {info.get('created_at', 'Unknown')}")
            print(f"  Disk size:   {info.get('disk_size_mb', 0)} MB")
            print(f"  Used space:  {info.get('used_space_mb', 0)} KB")
            print(f"  Free space:  {info.get('free_space_mb', 0)} MB")
            print(f"  Files:       {info.get('file_count', 0)}")
 
            # Show files if available and accessible
            files = info.get('files_list', [])
            if files:
                logger.info(f"Found {len(files)} files in vault")
                print(f"\n  Files in vault:")
                for file_path in files:
                    # Show size of each file in KB
                    file_info = manager.get_file_info(args.vault_name, file_path, password, key)
                    if file_info and 'size' in file_info:
                        size_kb = file_info['size'] // 1024
                        print(f"    - {file_path} ({size_kb} KB)")
                    else:
                        print(f"    - {file_path}")
                print(f"\nTotal: {len(files)} file(s)")
            elif password or key:
                logger.info("Vault is empty")
                print(f"\n  No files in vault")

        elif args.vault_command == 'delete':
            if not args.vault_name or args.vault_name in ['--help', '-h', 'help']:
                print("Usage: obfutil vault delete <vault_name>")
                print("Example: obfutil vault delete my_vault")
                return
                
            logger.info(f"Attempting to delete vault: {args.vault_name}")
            
            # Check if vault exists
            if not manager.vault_exists(args.vault_name):
                logger.warning(f"Vault not found for deletion: {args.vault_name}")
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                return
                
            confirm = input(f"WARNING: Are you sure you want to DELETE vault '{args.vault_name}'? This cannot be undone! [y/N]: ")
            if confirm.lower() == 'y':
                success = manager.delete_vault(args.vault_name)
                if success:
                    logger.info(f"Vault deleted successfully: {args.vault_name}")
                    print(f"SUCCESS: Vault '{args.vault_name}' deleted successfully")
                else:
                    logger.error(f"Failed to delete vault: {args.vault_name}")
                    print(f"ERROR: Failed to delete vault '{args.vault_name}'")
            else:
                logger.info("Vault deletion cancelled by user")
                print("Deletion cancelled.")

        elif args.vault_command == 'add':
            if not args.vault_name or args.vault_name in ['--help', '-h', 'help']:
                print("Usage: obfutil vault add <vault_name> <file_path> [internal_path] --password [--key-file] [--move]")
                print("Example: obfutil vault add my_vault document.txt --password")
                print("Example: obfutil vault add my_vault secret.txt --password --move")
                return

            file_path = args.file_path
            if not file_path:
                logger.error("File path not provided for add command")
                print("ERROR: File path required")
                print("Usage: obfutil vault add <vault_name> <file_path> [internal_path] --password [--move]")
                return

            internal_path = args.internal_path  # optional internal path
            
            password = None
            key = None
            
            if args.key_file:
                try:
                    key = load_key_from_file(DEFAULT_KEY_PATH)
                    logger.debug("Using key file for vault operation")
                except FileNotFoundError:
                    logger.error(f"Key file not found: {DEFAULT_KEY_PATH}")
                    print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
                logger.debug("Using password for vault operation")
            else:
                logger.error("No encryption method specified for vault operation")
                print("ERROR: Specify --password or --key-file")
                return

            # Pass move parameter
            success = manager.add_file_to_vault(args.vault_name, file_path, internal_path, password, key, move=args.move)

        elif args.vault_command == 'extract':
            if not args.vault_name:
                logger.error("Vault name not provided for extract command")
                print("Usage: obfutil vault extract <vault_name> <internal_path> <output_path> --password [--key-file]")
                print("Example: obfutil vault extract my_vault document.txt ./restored.txt --password")
                return

            internal_path = args.file_path
            if not internal_path:
                logger.error("Internal path not provided for extract command")
                print("ERROR: Internal path required")
                print("Usage: obfutil vault extract <vault_name> <internal_path> <output_path> --password")
                return

            output_path = args.internal_path
            if not output_path:
                logger.error("Output path not provided for extract command")
                print("ERROR: Output path required")
                print("Usage: obfutil vault extract <vault_name> <internal_path> <output_path> --password")
                return
            
            password = None
            key = None
            
            if args.key_file:
                try:
                    key = load_key_from_file(DEFAULT_KEY_PATH)
                except FileNotFoundError:
                    print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
            else:
                print("ERROR: Specify --password or --key-file")
                return

            logger.info(f"Extract: vault={args.vault_name}, file={internal_path}, output={output_path}")
            
            success = manager.extract_file_from_vault(args.vault_name, internal_path, output_path, password, key)
            
            if not success:
                # Show available files in vault
                files = manager.list_files_in_vault(args.vault_name, password, key)
                if files is None:
                    print("ERROR: Failed to access vault - wrong password or corrupted file")
                elif files:
                    print(f"ERROR: File '{internal_path}' not found in vault '{args.vault_name}'")
                    print(f"Available files in vault:")
                    for f in files:
                        print(f"  - {f}")
                else:
                    print(f"ERROR: Vault '{args.vault_name}' is empty")

        elif args.vault_command == 'files':
            if not args.vault_name:
                logger.error("Vault name not provided for files command")
                print("ERROR: Vault name required")
                return

            password = None
            key = None

            if args.key_file:
                try:
                    key = load_key_from_file(DEFAULT_KEY_PATH)
                    logger.debug("Using key file for vault operation")
                except FileNotFoundError:
                    logger.error(f"Key file not found: {DEFAULT_KEY_PATH}")
                    print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
                logger.debug("Using password for vault operation")
            else:
                logger.error("No encryption method specified for vault operation")
                print("ERROR: Specify --password or --key-file")
                return

            # Check if vault exists
            if not manager.vault_exists(args.vault_name):
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                print("Available vaults:")
                vaults = manager.list_vaults()
                for vault in vaults:
                    status = "[OK]" if vault.get('status') != 'missing' else "[MISSING]"
                    print(f"  {status} {vault['name']}")
                return

            files = manager.list_files_in_vault(args.vault_name, password, key)

            if files is None:
                # Vault exists but cannot be opened - wrong password
                print(f"ERROR: Failed to open vault '{args.vault_name}' - invalid password or corrupted file")
            elif not files:
                # Vault opened but empty
                print(f"No files found in vault '{args.vault_name}'")
            else:
                # Vault opened and has files
                logger.info(f"Displaying {len(files)} files from vault: {args.vault_name}")
                print(f"\n=== Files in vault '{args.vault_name}' ===")
                print("-" * 40)
                for file_path in files:
                    print(f"  {file_path}")
                print(f"\nTotal: {len(files)} file(s)")

        elif args.vault_command == 'remove':
            if not args.vault_name or args.vault_name in ['--help', '-h', 'help']:
                print("Usage: obfutil vault remove <vault_name> <internal_path> --password [--key-file]")
                print("Example: obfutil vault remove my_vault document.txt --password")
                return

            internal_path = args.file_path
            if not internal_path:
                logger.error("Internal path not provided for remove command")
                print("ERROR: Internal path required")
                print("Usage: obfutil vault remove <vault_name> <internal_path> --password")
                return
            
            password = None
            key = None
            
            if args.key_file:
                try:
                    key = load_key_from_file(DEFAULT_KEY_PATH)
                    logger.debug("Using key file for vault operation")
                except FileNotFoundError:
                    logger.error(f"Key file not found: {DEFAULT_KEY_PATH}")
                    print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
                logger.debug("Using password for vault operation")
            else:
                logger.error("No encryption method specified for vault operation")
                print("ERROR: Specify --password or --key-file")
                return

            success = manager.remove_file_from_vault(args.vault_name, internal_path, password, key)
        
        else:
            logger.warning(f"Unknown vault subcommand: {args.vault_command}")
            show_vault_help(lang)
            
    except Exception as e:
        logger.error(f"Unexpected error in vault command: {e}")
        print(f"ERROR: {e}")