import sys, glob, os, argparse
from pathlib import Path

from obfutil.utils.logger import get_logger
from obfutil.utils.localization import get_translation, SUPPORTED_LANGUAGES
from obfutil.utils.file_utils import read_file_safe, write_file_safe, open_file_in_editor
from obfutil.utils.interface import (
                                    show_menu, show_example_cmds,
                                    show_system_status, show_configuration
                                    )
from obfutil.obfuscation.core import obfuscate_code
from obfutil.crypto.encryption import (
                                        generate_key_file, load_key_from_file, 
                                        generate_password, input_password,
                                        encrypt_file, decrypt_file,
                                        encrypt_file_with_integrity, decrypt_file_with_integrity, verify_file_integrity
                                       )
from obfutil.config import load_config, update_language, VERSION, DEFAULT_KEY_PATH, DEFAULT_LANG
from obfutil.vault.commands import handle_vault_command

log = get_logger("MAIN")

def main():
    log.info("Program started")

    cfg = load_config()
    lang = cfg.get("language", "en")
    key_path = cfg.get("key_path", DEFAULT_KEY_PATH)

    if '--lang' in sys.argv:
        lang_index = sys.argv.index('--lang')
        if lang_index + 1 < len(sys.argv):
            new_lang = sys.argv[lang_index + 1].lower()
            if new_lang not in SUPPORTED_LANGUAGES:
                print(f"ERROR: Unsupported language: {new_lang}")
                print(f"Supported languages: {', '.join(SUPPORTED_LANGUAGES)}")
                return
            try:
                update_language(new_lang)
                lang = new_lang
                log.info(f"Language updated to: {lang}")
                sys.argv.pop(lang_index)
                sys.argv.pop(lang_index)
            except ValueError as e:
                log.error(str(e))
                print(f"ERROR: {str(e)}")
                return

    if len(sys.argv) > 1 and sys.argv[1] == 'vault':
        vault_parser = argparse.ArgumentParser(description="Vault operations", add_help=False)
        vault_parser.add_argument("vault_command", nargs="?", help="Vault subcommand")
        vault_parser.add_argument("vault_name", nargs="?", help="Vault name")
        vault_parser.add_argument("file_path", nargs="?", help="File path")
        vault_parser.add_argument("internal_path", nargs="?", help="Internal path in vault")
        vault_parser.add_argument("output_path", nargs="?", help="Output path for extraction")
        vault_parser.add_argument("--password", action="store_true", help="Use password encryption")
        vault_parser.add_argument("--key-file", action="store_true", help="Use key file encryption")
        vault_parser.add_argument("--size", type=int, help="Vault size in MB")
        vault_parser.add_argument("--move", action="store_true", help="Move file to vault (delete original)")
        vault_parser.add_argument("--help", action="store_true", help="Show vault help")
        vault_parser.add_argument("--lang", type=str, help="Set language (en/ru/de)")
        
        vault_args = vault_parser.parse_args(sys.argv[2:])
        
        if vault_args.lang:
            new_lang = vault_args.lang.lower()
            if new_lang not in SUPPORTED_LANGUAGES:
                print(f"ERROR: Unsupported language: {new_lang}")
                print(f"Supported languages: {', '.join(SUPPORTED_LANGUAGES)}")
                return
            try:
                update_language(new_lang)
                lang = new_lang
                log.info(f"Language updated to: {lang}")
            except ValueError as e:
                log.error(str(e))
                print(f"ERROR: {str(e)}")
                return
        
        if vault_args.help or not vault_args.vault_command:
            from obfutil.utils.interface import show_vault_help
            show_vault_help(lang)
            return
            
        handle_vault_command(vault_args, lang)
        return

    main_parser = argparse.ArgumentParser(
        description="ObfUtil - Advanced encryption tool",
        add_help=False
    )
    
    main_parser.add_argument("command", nargs="?", help="Main command")
    main_parser.add_argument("file", nargs="?", help="Target file")
    main_parser.add_argument("--password", action="store_true", help="Use password encryption")
    main_parser.add_argument("--key-file", action="store_true", help="Use key file encryption")
    main_parser.add_argument("--gen-key", action="store_true", help="Generate encryption key")
    main_parser.add_argument("--gen-pass", type=int, help="Generate password with specified length")
    main_parser.add_argument("--lang", type=str, help="Set language (en/ru/de)")
    main_parser.add_argument("-h", "--help", action="store_true", help="Show help")
    main_parser.add_argument("--cmds", action="store_true", help="Show usage examples")
    main_parser.add_argument("--show", action="store_true", help="Show configuration")

    args = main_parser.parse_args()
    
    log.info(f"Command: {args.command}, file: {args.file}")

    if args.lang:
        new_lang = args.lang.lower()
        if new_lang not in SUPPORTED_LANGUAGES:
            print(f"ERROR: Unsupported language: {new_lang}")
            print(f"Supported languages: {', '.join(SUPPORTED_LANGUAGES)}")
            return
        try:
            update_language(new_lang)
            lang = new_lang
            log.info(f"Language updated in config → {lang}")
        except ValueError as e:
            log.error(str(e))
            print(get_translation(lang, "error").format(str(e)))
            return

    if args.cmds:
        log.info("Showing complete examples")
        show_example_cmds(lang)
        return

    if args.help:
        log.info("Showing menu")
        show_menu(lang)
        return

    if args.gen_pass is not None:
        ln = max(args.gen_pass, 8)
        log.info(f"Generating random password (len={ln})")
        try:
            password = generate_password(ln)
            print(f"{get_translation(lang, 'generated_pass')} {password}")
        except Exception as e:
            log.error(f"Password generation failed: {e}")
        return

    if args.gen_key:
        log.info("Generating encryption key")
        if Path(key_path).exists():
            confirm = input(f"Key file already exists at {key_path}. Overwrite? [y/N]: ").strip().lower()
            if confirm != "y":
                log.info("Key generation cancelled by user")
                return

        try:
            key = generate_key_file(key_path)
            print(f"{get_translation(lang, 'gen_key_created')} {key_path}")
            log.info(f"Key generated and saved to: {key_path}")
        except Exception as e:
            log.error(f"Key generation failed: {e}")
        return

    if not args.command:
        log.info("No command specified, showing menu")
        show_menu(lang)
        return

    # Commands that don't need a file
    no_file_commands = ['status', 'config']
    
    # Commands that need a file
    file_commands = [
        'encrypt', 'decrypt', 'view', 'obfuscate', 
        'encrypt-int', 'decrypt-int', 'verify-int',
        'batch-encrypt', 'batch-decrypt'
    ]
    
    # Only commands that need a file
    if args.command in file_commands and not args.file:
        log.warning(f"Command '{args.command}' called without target")
        print(f"ERROR: Target required for command '{args.command}'")
        print(f"Usage: obfutil {args.command} <file> [options]")
        return

    # target_file is used only with commands that need a file
    target_file = args.file if args.command in file_commands else None
    
    if args.command == "status":
        log.info("Showing system status")
        try:
            from obfutil.core.api import api
            result = api.get_system_status()
            if result['success']:
                show_system_status(result, lang)
            else:
                print(f"ERROR: {result.get('message', 'Failed to get system status')}")
        except Exception as e:
            log.error(f"Status command failed: {e}")
            print(f"ERROR: Failed to get system status: {e}")

    elif args.command == "config":
        log.info("Managing configuration")
        try:
            from obfutil.core.api import api
            
            if args.show:
                result = api.get_config()
                if result['success']:
                    from obfutil.utils.interface import show_configuration
                    show_configuration(result, lang)
                else:
                    print(f"ERROR: {result.get('message', 'Failed to get configuration')}")
            elif args.lang:
                new_lang = args.lang.lower()
                if new_lang not in SUPPORTED_LANGUAGES:
                    print(f"ERROR: Unsupported language: {new_lang}")
                    print(f"Supported languages: {', '.join(SUPPORTED_LANGUAGES)}")
                    return
                
                result = api.update_config({'language': new_lang})
                if result['success']:
                    print(f"SUCCESS: Language updated to {new_lang}")
                else:
                    print(f"ERROR: {result.get('message', 'Failed to update language')}")
            else:
                print("Usage: obfutil config --lang <en/ru/de> OR obfutil config --show")
                print("Examples:")
                print("  obfutil config --lang ru      # Change language to Russian")
                print("  obfutil config --show         # Show current configuration")
                
        except Exception as e:
            log.error(f"Config command failed: {e}")
            print(f"ERROR: Configuration operation failed: {e}")

    elif args.command == "encrypt":
        if args.key_file:
            try:
                key = load_key_from_file(key_path)
                encrypt_file(target_file, key=key, lang=lang)
            except Exception as e:
                log.error(f"Encryption error: {e}")
        elif args.password:
            try:
                pw = input_password(get_translation(lang, "password_prompt"))
                encrypt_file(target_file, password=pw, lang=lang)
            except Exception as e:
                log.error(f"Encryption error: {e}")
        else:
            print("ERROR: Specify --password or --key-file for encryption")
            show_menu(lang)

    elif args.command == "decrypt":
        if args.key_file:
            try:
                key = load_key_from_file(key_path)
                decrypt_file(target_file, key=key, edit_mode=True, lang=lang)
            except Exception as e:
                log.error(f"Decryption error: {e}")
        elif args.password:
            try:
                pw = input_password(get_translation(lang, "password_prompt"))
                decrypt_file(target_file, password=pw, edit_mode=True, lang=lang)
            except Exception as e:
                log.error(f"Decryption error: {e}")
        else:
            print("ERROR: Specify --password or --key-file for decryption")
            show_menu(lang)

    elif args.command == "view":
        if args.key_file:
            try:
                key = load_key_from_file(key_path)
                decrypt_file(target_file, key=key, edit_mode=False, lang=lang)
            except Exception as e:
                log.error(f"View error: {e}")
        elif args.password:
            try:
                pw = input_password(get_translation(lang, "password_prompt"))
                decrypt_file(target_file, password=pw, edit_mode=False, lang=lang)
            except Exception as e:
                log.error(f"View error: {e}")
        else:
            print("ERROR: Specify --password or --key-file for viewing")
            show_menu(lang)

    elif args.command == "obfuscate":
        if not target_file.endswith(".py"):
            log.error("Obfuscation target is not a Python file")
            print("ERROR: Target must be a .py script")
            return

        try:
            log.info(f"Reading file for obfuscation: {target_file}")
            code = Path(target_file).read_text(encoding="utf-8")
            log.info("Starting obfuscation")
            obf = obfuscate_code(code)

            out = target_file.replace(".py", "") + "_obf.py"
            Path(out).write_text(obf, encoding="utf-8")

            log.info(f"Obfuscation complete → {out}")
            print(f"{get_translation(lang, 'file_obfuscated')} {out}")
        except Exception as e:
            log.error(f"Obfuscation error: {e}")

    elif args.command == "encrypt-int":
        if args.key_file:
            try:
                key = load_key_from_file(key_path)
                encrypt_file_with_integrity(target_file, key=key, lang=lang)
            except Exception as e:
                log.error(f"Encryption with integrity error: {e}")
        elif args.password:
            try:
                pw = input_password(get_translation(lang, "password_prompt"))
                encrypt_file_with_integrity(target_file, password=pw, lang=lang)
            except Exception as e:
                log.error(f"Encryption with integrity error: {e}")
        else:
            print("ERROR: Specify --password or --key-file")
            show_menu(lang)

    elif args.command == "verify-int":
        if args.key_file:
            try:
                key = load_key_from_file(key_path)
                verify_file_integrity(target_file, key=key, lang=lang)
            except Exception as e:
                log.error(f"Integrity verification error: {e}")
        elif args.password:
            try:
                pw = input_password(get_translation(lang, "password_prompt"))
                verify_file_integrity(target_file, password=pw, lang=lang)
            except Exception as e:
                log.error(f"Integrity verification error: {e}")
        else:
            print("ERROR: Specify --password or --key-file")
            show_menu(lang)

    elif args.command == "decrypt-int":
        if args.key_file:
            try:
                key = load_key_from_file(key_path)
                decrypt_file_with_integrity(target_file, key=key, edit_mode=True, lang=lang)
            except Exception as e:
                log.error(f"Decryption with integrity error: {e}")
        elif args.password:
            try:
                pw = input_password(get_translation(lang, "password_prompt"))
                decrypt_file_with_integrity(target_file, password=pw, edit_mode=True, lang=lang)
            except Exception as e:
                log.error(f"Decryption with integrity error: {e}")
        else:
            print("ERROR: Specify --password or --key-file")
            show_menu(lang)

    elif args.command == "batch-encrypt":
        if not args.file:
            log.error("File pattern not provided for batch-encrypt")
            print("ERROR: File pattern required (e.g., *.txt)")
            return
            
        log.info(f"Batch encrypting files: {args.file}")
        try:
            import glob
            file_paths = glob.glob(args.file)
            if not file_paths:
                print(f"No files found matching pattern: {args.file}")
                return
                
            print(f"Found {len(file_paths)} file(s) to encrypt")
            
            password = None
            key = None
            
            if args.key_file:
                try:
                    key = load_key_from_file(key_path)
                except Exception as e:
                    log.error(f"Key file error: {e}")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
            else:
                print("ERROR: Specify --password or --key-file for batch encryption")
                return
                
            from obfutil.core.api import api
            result = api.encrypt_files_batch(file_paths, password, key, lang)
            
            if result['success']:
                print(f"SUCCESS: {result['successful']}/{result['processed']} files encrypted")
                if result['failed'] > 0:
                    print(f"WARNING: {result['failed']} files failed")
    
                # Show extended statistics
                from obfutil.utils.interface import show_batch_stats
                show_batch_stats(result, lang)
                
        except Exception as e:
            log.error(f"Batch encrypt failed: {e}")
            print(f"ERROR: Batch encryption failed: {e}")

    elif args.command == "batch-decrypt":
        if not args.file:
            log.error("File pattern not provided for batch-decrypt")
            print("ERROR: File pattern required (e.g., *.enc)")
            return
            
        log.info(f"Batch decrypting files: {args.file}")
        try:
            import glob
            file_paths = glob.glob(args.file)
            if not file_paths:
                print(f"No files found matching pattern: {args.file}")
                return
                
            print(f"Found {len(file_paths)} file(s) to decrypt")
            
            password = None
            key = None
            
            if args.key_file:
                try:
                    key = load_key_from_file(key_path)
                except Exception as e:
                    log.error(f"Key file error: {e}")
                    return
            elif args.password:
                password = input_password(get_translation(lang, "password_prompt"))
            else:
                print("ERROR: Specify --password or --key-file for batch decryption")
                return
                
            from obfutil.core.api import api
            result = api.decrypt_files_batch(file_paths, password, key, lang)
            
            if result['success']:
                print(f"SUCCESS: {result['successful']}/{result['processed']} files encrypted")
                if result['failed'] > 0:
                    print(f"WARNING: {result['failed']} files failed")
    
                # Show extended statistics
                from obfutil.utils.interface import show_batch_stats
                show_batch_stats(result, lang)
                
        except Exception as e:
            log.error(f"Batch decrypt failed: {e}")
            print(f"ERROR: Batch decryption failed: {e}")
    
    elif args.command == "analyze":
        log.info(f"Analyzing vault: {args.vault_name}")
        try:
            from obfutil.core.api import api
            result = api.analyze_vault_usage(
                args.vault_name, 
                password=pw if args.password else None,
                key=key if args.key_file else None
            )
            if result['success']:
                from obfutil.utils.interface import show_vault_analysis
                show_vault_analysis(result, lang)
            else:
                print(f"ERROR: {result.get('message', 'Vault analysis failed')}")
        except Exception as e:
            log.error(f"Vault analysis error: {e}")
    
    else:
        log.error(f"Invalid command: {args.command}")
        print(f"Invalid command: {args.command}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        from obfutil.utils.logger import log_exception
        msg = log_exception(log, e)
        print(f"FATAL ERROR: {msg}")
        input("\nPress Enter to exit...")