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
        if not args.vault_command:
            show_vault_help(lang)
            return
            
        manager = VaultManager()
        
        if args.vault_command == 'preview':
            if not args.vault_name:
                print("Usage: obfutil vault preview <vault_name> [--password|--key-file]")
                return
                
            password, key = _get_auth_method(args, lang, logger)
            preview = manager.quick_vault_preview(args.vault_name, password, key)
            
            if preview.get('status') == 'success':
                print(f"\n=== Vault: {args.vault_name} ===")
                print(f"Files: {preview['file_count']}")
                print(f"Size: {preview['total_size_mb']} MB")
                if preview['files']:
                    print(f"\nFiles:")
                    for file_info in preview['files']:
                        print(f"  - {file_info['name']} ({file_info['size_kb']} KB)")
            else:
                print(f"ERROR: {preview.get('message', 'Failed to preview')}")
        
        elif args.vault_command == 'verify':
            if not args.vault_name:
                print("Usage: obfutil vault verify <vault_name> [--deep] --password/--key-file")
                return
                
            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file for verification")
                return

            deep_check = getattr(args, 'deep', False)
            print(f"Verifying vault '{args.vault_name}'...")
            
            results = manager.verify_vault_integrity(args.vault_name, password, key, deep_check)
            
            print(f"\n=== Vault Integrity: {args.vault_name} ===")
            print("=" * 40)
            
            if results.get('status') == 'success':
                overall_status = results.get('overall_status', 'unknown').upper()
                print(f"Overall Status: {overall_status}")
                
                if deep_check:
                    print(f"Checks Passed: {results.get('checks_passed', 0)}/{results.get('checks_total', 0)}")
                    print(f"Files Checked: {results.get('files_checked', 0)}")
                    
                    if results.get('issues'):
                        print(f"\nIssues Found:")
                        for issue in results.get('issues', []):
                            print(f"  - {issue}")
                    else:
                        print(f"\n✓ All checks passed - vault is healthy")
                else:
                    # Quick check - FIXED output
                    print(f"Files: {results.get('file_count', 0)}")
                    print(f"Header: {'✓ OK' if results.get('header_ok') else '✗ FAILED'}")
                    print(f"File Table: {'✓ OK' if results.get('file_table_ok') else '✗ FAILED'}")
                    
                    if results.get('overall_ok'):
                        print(f"\n✓ Quick check passed - vault structure is valid")
                    else:
                        print(f"\n✗ Quick check failed - vault structure issues detected")
            else:
                error_msg = results.get('message', 'Unknown verification error')
                print(f"ERROR: {error_msg}")
            
            print("=" * 40)
        
        elif args.vault_command == 'debug-file':
            if not args.vault_name or not args.file_path:
                print("Usage: obfutil vault debug-file <vault_name> <internal_path> --password/--key-file")
                return
                
            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file")
                return

            def debug_op(vault):
                vault.debug_file_info(args.file_path)
                return {'status': 'success'}
            
            result = manager.secure_operation(args.vault_name, debug_op, password, key)
            if result and result.get('status') == 'success':
                print(f"Debug info logged for file: {args.file_path}")
            else:
                print(f"ERROR: Failed to debug file")
        
        elif args.vault_command == 'health':
            if not args.vault_name:
                print("Usage: obfutil vault health <vault_name> [--password|--key-file]")
                return
                
            password, key = _get_auth_method(args, lang, logger)
            health = manager.get_vault_health(args.vault_name, password, key)
            
            print(f"\n=== Vault Health: {args.vault_name} ===")
            print("=" * 35)
            print(f"Status: {health.get('status', 'unknown')}")
            print(f"Files: {health.get('file_count', 0)}")
            print("=" * 35)
        
        elif args.vault_command == 'storage':
            if not args.vault_name:
                print("Usage: obfutil vault storage <vault_name> --password/--key-file")
                return
                
            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file for storage info")
                return

            storage_info = manager.check_vault_storage(args.vault_name, password, key)
            
            print(f"\n=== Storage: {args.vault_name} ===")
            print("=" * 40)
            if storage_info.get('status') == 'ok':
                print(f"Capacity: {storage_info.get('total_size_mb', 0)} MB")
                print(f"Used: {storage_info.get('used_space_mb', 0)} MB")
                print(f"Free: {storage_info.get('free_space_mb', 0)} MB")
                print(f"Usage: {storage_info.get('usage_percentage', 0):.1f}%")
                print(f"Files: {storage_info.get('file_count', 0)}")
            else:
                print(f"ERROR: {storage_info.get('message', 'Failed to get storage info')}")
            print("=" * 40)
        
        elif args.vault_command == 'secure-delete':
            if not args.vault_name:
                print("Usage: obfutil vault secure-delete <vault_name>")
                return
                
            if not manager.vault_exists(args.vault_name):
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                return
                
            confirm = input(f"SECURE DELETE vault '{args.vault_name}'? Type 'DELETE' to confirm: ")
            if confirm == 'DELETE':
                success = manager.secure_vault_delete(args.vault_name)
                if success:
                    print(f"SUCCESS: Vault '{args.vault_name}' securely deleted")
                else:
                    print(f"ERROR: Failed to delete vault")
            else:
                print("Deletion cancelled.")

        # ===== EXISTING COMMANDS =====
        
        elif args.vault_command == 'create':
            if not args.vault_name:
                print("Usage: obfutil vault create <vault_name> --size <MB> --password [--key-file]")
                return
                
            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file for creation")
                return

            size = args.size or 100
            if size < 1 or size > 1024:
                print("ERROR: Size must be between 1MB and 1024MB")
                return
                
            success = manager.create_vault(args.vault_name, size, password, key)
            if success:
                print(f"SUCCESS: Vault '{args.vault_name}' created")
            else:
                print(f"ERROR: Failed to create vault")
        
        elif args.vault_command == 'list':
            vaults = manager.list_vaults()
            if not vaults:
                print("No vaults found.")
                return

            print("\n=== Vaults ===")
            print("=" * 40)
            print(f"{'Status':<8} {'Name':<15} {'Size':<8} {'Files':<6}")
            print("=" * 40)

            for vault in vaults:
                status = vault.get('status', 'UNKNOWN')
                name = vault['name']
                size = f"{vault.get('size_mb', 0)}MB"
                files = vault.get('file_count', '?')  # Will show '?' if cannot access
                health = vault.get('health', 'unknown')

                print(f"{status:<8} {name:<15} {size:<8} {files:<6}")

            print(f"\nTotal: {len(vaults)} vault(s)")
            print("\nNote: File count requires --password/--key-file to access vault contents")

        elif args.vault_command == 'info':
            if not args.vault_name:
                print("ERROR: Vault name required")
                return

            exists = manager.vault_exists(args.vault_name)
            if not exists:
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                return

            password, key = _get_auth_method(args, lang, logger)
            
            info = manager.get_vault_info(args.vault_name, password, key)
            if not info:
                print(f"ERROR: Could not read vault info")
                return

            print(f"\n=== Vault Info: {args.vault_name} ===")
            print("=" * 50)
            print(f"Status: {info.get('status', 'UNKNOWN')}")
            print(f"Created: {info.get('created_at', 'Unknown')}")
            print(f"Size: {info.get('total_size_mb', 0)} MB")
            print(f"Used: {info.get('used_space_mb', 0)} MB")
            print(f"Free: {info.get('free_space_mb', 0)} MB")
            print(f"Files: {info.get('file_count', 0)}")

            files = info.get('files_list', [])
            if files:
                print(f"\nFiles:")
                for file_path in files:
                    print(f"  - {file_path}")
            print("=" * 50)

        elif args.vault_command == 'add':
            if not args.vault_name or not args.file_path:
                print("Usage: obfutil vault add <vault_name> <file_path> [internal_path] --password [--move]")
                return

            internal_path = args.internal_path
            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file")
                return

            success = manager.add_file_to_vault(args.vault_name, args.file_path, internal_path, password, key, move=getattr(args, 'move', False))
            if success:
                print(f"SUCCESS: File added to vault '{args.vault_name}'")
            else:
                print(f"ERROR: Failed to add file")

        elif args.vault_command == 'extract':
            if not args.vault_name or not args.file_path or not args.internal_path:
                print("Usage: obfutil vault extract <vault_name> <internal_path> <output_path> --password")
                return

            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file")
                return

            success = manager.extract_file_from_vault(args.vault_name, args.file_path, args.internal_path, password, key)
            if success:
                print(f"SUCCESS: File extracted from vault '{args.vault_name}'")
            else:
                print(f"ERROR: Failed to extract file")

        elif args.vault_command == 'files':
            if not args.vault_name:
                print("ERROR: Vault name required")
                return

            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file")
                return

            if not manager.vault_exists(args.vault_name):
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                return

            files = manager.list_files_in_vault(args.vault_name, password, key)

            if files is None:
                print(f"ERROR: Failed to open vault - invalid password or corrupted")
            elif not files:
                print(f"No files in vault '{args.vault_name}'")
            else:
                print(f"\n=== Files in '{args.vault_name}' ===")
                print("-" * 40)
                for file_path in files:
                    print(f"  {file_path}")
                print(f"\nTotal: {len(files)} file(s)")

        elif args.vault_command == 'remove':
            if not args.vault_name or not args.file_path:
                print("Usage: obfutil vault remove <vault_name> <internal_path> --password")
                return
            
            password, key = _get_auth_method(args, lang, logger)
            if password is None and key is None:
                print("ERROR: Specify --password or --key-file")
                return

            success = manager.remove_file_from_vault(args.vault_name, args.file_path, password, key)
            if success:
                print(f"SUCCESS: File removed from vault '{args.vault_name}'")
            else:
                print(f"ERROR: Failed to remove file")

        elif args.vault_command == 'delete':
            if not args.vault_name:
                print("Usage: obfutil vault delete <vault_name>")
                return
                
            if not manager.vault_exists(args.vault_name):
                print(f"ERROR: Vault '{args.vault_name}' not found!")
                return
                
            confirm = input(f"Delete vault '{args.vault_name}'? [y/N]: ")
            if confirm.lower() == 'y':
                success = manager.delete_vault(args.vault_name)
                if success:
                    print(f"SUCCESS: Vault '{args.vault_name}' deleted")
                else:
                    print(f"ERROR: Failed to delete vault")
            else:
                print("Deletion cancelled.")
        
        else:
            print(f"ERROR: Unknown vault command: {args.vault_command}")
            show_vault_help(lang)
            
    except Exception as e:
        logger.error(f"Vault command error: {e}")
        print(f"ERROR: {e}")

def _get_auth_method(args, lang, logger):
    """Helper to get authentication method from args - FIXED VERSION"""
    password = None
    key = None
    
    # Check if password or key-file flags are present
    if hasattr(args, 'key_file') and args.key_file:
        try:
            key = load_key_from_file(DEFAULT_KEY_PATH)
            logger.debug("Using key file for authentication")
        except FileNotFoundError:
            print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
            print("Generate a key first with: obfutil --gen-key")
    elif hasattr(args, 'password') and args.password:
        password = input_password(get_translation(lang, "password_prompt"))
        logger.debug("Using password for authentication")
    
    return password, key