"""
Vault CLI Commands - Handles all vault-related CLI operations
Version 3.4: Added new commands:
- vault search: Search files by pattern
- vault rename: Rename files inside vault
- vault du: Show disk usage by folder
- vault stats: Detailed vault statistics
- Added --force flag for add command
"""

from pathlib import Path
import time
import sys
import os
from typing import Optional, Tuple

from obfutil.vault.manager import VaultManager
from obfutil.crypto.encryption import input_password, load_key_from_file
from obfutil.config import DEFAULT_KEY_PATH
from obfutil.utils.localization import get_translation
from obfutil.utils.logger import get_logger
from obfutil.utils.interface import show_vault_help


def handle_vault_command(args, lang):
    """
    Handle vault commands - main dispatcher
    
    Args:
        args: Parsed command line arguments
        lang: Current language setting
    """
    logger = get_logger("VAULT_CLI")
    
    try:
        if not args.vault_command:
            show_vault_help(lang)
            return
            
        manager = VaultManager()
        
        # ========== NEW COMMANDS FOR 3.4 ==========
        
        if args.vault_command == 'search':
            _handle_search(manager, args, lang, logger)
        
        elif args.vault_command == 'rename':
            _handle_rename(manager, args, lang, logger)
        
        elif args.vault_command == 'du':
            _handle_du(manager, args, lang, logger)
        
        elif args.vault_command == 'stats':
            _handle_stats(manager, args, lang, logger)
        
        # ========== EXISTING COMMANDS ==========
        
        elif args.vault_command == 'preview':
            _handle_preview(manager, args, lang, logger)
        
        elif args.vault_command == 'verify':
            _handle_verify(manager, args, lang, logger)
        
        elif args.vault_command == 'debug-file':
            _handle_debug_file(manager, args, lang, logger)
        
        elif args.vault_command == 'storage':
            _handle_storage(manager, args, lang, logger)
        
        elif args.vault_command == 'delete':
            _handle_delete(manager, args, lang, logger)
        
        elif args.vault_command == 'create':
            _handle_create(manager, args, lang, logger)
        
        elif args.vault_command == 'list':
            _handle_list(manager, args, lang, logger)
        
        elif args.vault_command == 'info':
            _handle_info(manager, args, lang, logger)
        
        elif args.vault_command == 'add':
            _handle_add(manager, args, lang, logger)
        
        elif args.vault_command == 'extract':
            _handle_extract(manager, args, lang, logger)
        
        elif args.vault_command == 'remove':
            _handle_remove(manager, args, lang, logger)
        
        else:
            print(f"Unknown vault command: {args.vault_command}")
            show_vault_help(lang)
            
    except Exception as e:
        logger.error(f"Vault command error: {e}")
        print(f"ERROR: {e}")


# ========== NEW HANDLERS FOR 3.4 ==========

def _handle_search(manager: VaultManager, args, lang: str, logger):
    """
    Search for files in vault
    Usage: obfutil vault search <vault_name> <pattern> [--type name|ext|contains] [--case] [--min-size MB] [--max-size MB] --password
    """
    if not args.vault_name or not args.file_path:
        print("Usage: obfutil vault search <vault_name> <pattern> [--type name|ext|contains] [--case] [--min-size MB] [--max-size MB] --password")
        return
        
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return
    
    # Get search parameters
    search_type = getattr(args, 'type', 'name')
    case_sensitive = getattr(args, 'case', False)
    min_size = getattr(args, 'min_size', None)
    max_size = getattr(args, 'max_size', None)
    
    # Convert sizes from MB to bytes
    if min_size:
        min_size = int(min_size * 1024 * 1024)
    if max_size:
        max_size = int(max_size * 1024 * 1024)
    
    pattern = args.file_path
    
    print(f"Searching vault '{args.vault_name}' for '{pattern}'...")
    
    results = manager.search_files_in_vault(
        args.vault_name, pattern, search_type, 
        case_sensitive, min_size, max_size,
        password, key
    )
    
    if not results:
        print("\nNo files found.")
        return
    
    print(f"\n=== Search Results: '{pattern}' ===")
    print("=" * 60)
    print(f"Found {len(results)} file(s)\n")
    
    # Display results in a table format
    print(f"{'Size':>10}  {'Added Date':<19}  {'Path'}")
    print("-" * 60)
    
    for file_info in results:
        # Убедимся что size_bytes есть
        size_bytes = file_info.get('size_bytes', file_info.get('size', 0))
        size_str = _format_size(size_bytes)
        added_date = file_info.get('added_date', 'Unknown')[:16]
        print(f"{size_str:>10}  {added_date:<19}  {file_info['path']}")
    
    # Show summary if filters were applied
    if min_size or max_size:
        print("\nFilters applied:")
        if min_size:
            print(f"  - Minimum size: {min_size / (1024*1024):.1f} MB")
        if max_size:
            print(f"  - Maximum size: {max_size / (1024*1024):.1f} MB")
    
    print("=" * 60)


def _handle_rename(manager: VaultManager, args, lang: str, logger):
    """
    Rename file in vault
    Usage: obfutil vault rename <vault_name> <old_path> <new_path> --password
    """
    if not args.vault_name or not args.file_path or not args.internal_path:
        print("Usage: obfutil vault rename <vault_name> <old_path> <new_path> --password")
        return
        
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return
    
    old_path = args.file_path
    new_path = args.internal_path
    
    print(f"Renaming '{old_path}' -> '{new_path}' in vault '{args.vault_name}'...")
    
    success = manager.rename_file_in_vault(args.vault_name, old_path, new_path, password, key)
    
    if success:
        print(f"SUCCESS: File renamed")
    else:
        print("ERROR: Failed to rename file")
        print("Possible reasons:")
        print("  - Source file not found")
        print("  - Target name already exists")
        print("  - Invalid path format")


def _handle_du(manager: VaultManager, args, lang: str, logger):
    """
    Show disk usage by folder in vault
    Usage: obfutil vault du <vault_name> --password
    """
    if not args.vault_name:
        print("Usage: obfutil vault du <vault_name> --password")
        return
        
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return
    
    print(f"Calculating disk usage for vault '{args.vault_name}'...")
    
    usage = manager.get_vault_folder_usage(args.vault_name, password, key)
    
    if not usage:
        print("Vault is empty or could not be accessed")
        return
    
    # Sort by size (largest first)
    sorted_usage = sorted(usage.items(), key=lambda x: x[1], reverse=True)
    total_size = sum(usage.values())
    
    print(f"\n=== Disk Usage: {args.vault_name} ===")
    print("=" * 55)
    print(f"{'Folder':<35} {'Size':>10} {'%':>8}")
    print("-" * 55)
    
    for folder, size in sorted_usage[:30]:  # Show top 30 folders
        size_str = _format_size(size)
        percent = (size / total_size * 100) if total_size > 0 else 0
        print(f"{folder:<35} {size_str:>10} {percent:>7.1f}%")
    
    if len(sorted_usage) > 30:
        print(f"... and {len(sorted_usage) - 30} more folders")
    
    print("-" * 55)
    print(f"{'TOTAL':<35} {_format_size(total_size):>10} {'100.0%':>8}")
    print("=" * 55)


def _handle_stats(manager: VaultManager, args, lang: str, logger):
    """
    Show detailed vault statistics
    Usage: obfutil vault stats <vault_name> --password
    """
    if not args.vault_name:
        print("Usage: obfutil vault stats <vault_name> --password")
        return
        
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return
    
    print(f"Gathering statistics for vault '{args.vault_name}'...")
    
    stats = manager.get_vault_statistics(args.vault_name, password, key)
    
    if not stats or stats.get('total_files', 0) == 0:
        print("Vault is empty")
        return
    
    print(f"\n{'='*55}")
    print(f"  Vault Statistics: {args.vault_name}")
    print(f"{'='*55}")
    
    # Basic stats
    print(f"\nBASIC STATISTICS")
    print(f"{'─'*40}")
    print(f"  Total Files:    {stats['total_files']:,}")
    print(f"  Total Size:     {_format_size(stats['total_size_bytes'])}")
    print(f"  Average Size:   {_format_size(stats['avg_size_kb'] * 1024)}")
    
    # File type distribution (top 10)
    if stats.get('file_types'):
        print(f"\nFILE TYPE DISTRIBUTION")
        print(f"{'─'*40}")
        print(f"{'Type':<20} {'Count':>8} {'Size':>12} {'%':>8}")
        print(f"{'─'*40}")
        
        sorted_types = sorted(stats['file_types'].items(), key=lambda x: x[1], reverse=True)[:15]
        for ext, count in sorted_types:
            size = stats.get('type_sizes', {}).get(ext, 0) * 1024 * 1024  # Convert MB to bytes
            percent = (size / stats['total_size_bytes'] * 100) if stats['total_size_bytes'] > 0 else 0
            print(f"  .{ext:<18} {count:>8,} {_format_size(size):>12} {percent:>7.1f}%")
    
    # Largest files (top 10)
    if stats.get('top_10_files'):
        print(f"\nLARGEST FILES")
        print(f"{'─'*40}")
        print(f"{'Size':>12}  {'File'}")
        print(f"{'─'*40}")
        
        for file_info in stats['top_10_files'][:10]:
            size_str = _format_size(file_info['size_bytes'])
            print(f"{size_str:>12}  {file_info['path']}")
    
    # Folder summary
    if stats.get('folder_summary'):
        print(f"\nFOLDER SUMMARY (Top 10 by size)")
        print(f"{'─'*40}")
        print(f"{'Folder':<30} {'Size':>10} {'%':>8}")
        print(f"{'─'*40}")
        
        for folder in stats['folder_summary'][:10]:
            size_str = _format_size(folder['size_bytes'])
            print(f"{folder['path']:<30} {size_str:>10} {folder['size_percent']:>7.1f}%")
    
    # Oldest and newest files
    if stats.get('oldest_file'):
        print(f"\nFILE AGES")
        print(f"{'─'*40}")
        print(f"  Oldest File:   {stats['oldest_file']['name']}")
        print(f"                 (added: {stats['oldest_file']['added_at']})")
    
    if stats.get('newest_file'):
        print(f"  Newest File:   {stats['newest_file']['name']}")
        print(f"                 (added: {stats['newest_file']['added_at']})")
    
    print(f"\n{'='*55}")


# ========== MODIFIED HANDLERS FOR 3.4 ==========

def _handle_add(manager: VaultManager, args, lang: str, logger):
    """
    Add file to vault with force option
    Usage: obfutil vault add <vault_name> <file_path> [internal_path] --password [--move] [--force]
    """
    if not args.vault_name or not args.file_path:
        print("Usage: obfutil vault add <vault_name> <file_path> [internal_path] --password [--move] [--force]")
        return

    internal_path = args.internal_path
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return

    # Check if source file exists
    source_file = Path(args.file_path)
    if not source_file.exists():
        print(f"ERROR: Source file not found: {args.file_path}")
        return

    # Check if vault exists
    if not manager.vault_exists(args.vault_name):
        print(f"ERROR: Vault '{args.vault_name}' not found!")
        print(f"Use 'obfutil vault list' to see available vaults")
        return

    # Check file size for warning
    file_size = source_file.stat().st_size
    if file_size > 100 * 1024 * 1024:  # >100MB
        print(f"Warning: File size is {_format_size(file_size)}")
        confirm = input("Continue? [y/N]: ")
        if confirm.lower() != 'y':
            print("Operation cancelled.")
            return

    force = getattr(args, 'force', False)
    move = getattr(args, 'move', False)
    
    success = manager.add_file_to_vault(
        args.vault_name, args.file_path, internal_path, 
        password, key, move=move, force=force
    )
    
    if not success:
        print("\nTip: Run 'obfutil vault storage' to check available space")


def _handle_extract(manager: VaultManager, args, lang: str, logger):
    """
    Extract file from vault
    Usage: obfutil vault extract <vault_name> <internal_path> <output_path> --password
    """
    if not args.vault_name or not args.file_path or not args.internal_path:
        print("Usage: obfutil vault extract <vault_name> <internal_path> <output_path> --password")
        return

    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return

    # Проверяем существование файла через preview
    preview = manager.quick_vault_preview(args.vault_name, password, key)
    if preview.get('status') == 'success':
        files = [f['name'] for f in preview.get('files', [])]
        if args.file_path not in files:
            print(f"ERROR: File '{args.file_path}' not found in vault")
            print("\nAvailable files:")
            for f in files[:10]:
                print(f"  - {f}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")
            return

    # Проверяем выходную директорию
    output_path = Path(args.internal_path)
    if output_path.exists():
        confirm = input(f"File '{output_path}' already exists. Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            print("Extraction cancelled.")
            return
    
    # Проверяем права на запись в директорию
    if output_path.parent.exists() and not os.access(output_path.parent, os.W_OK):
        print(f"ERROR: Cannot write to directory: {output_path.parent}")
        return

    success = manager.extract_file_from_vault(
        args.vault_name, args.file_path, args.internal_path, password, key
    )
    
    if not success:
        print("\nTip: Check if file exists using 'obfutil vault preview'")


# ========== EXISTING HANDLERS (with minor improvements) ==========

def _handle_preview(manager: VaultManager, args, lang: str, logger):
    """Show vault preview"""
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
                size_str = _format_size(file_info['size_bytes'])
                print(f"  - {file_info['name']} ({size_str})")
    else:
        print(f"ERROR: {preview.get('message', 'Failed to preview')}")


def _handle_verify(manager: VaultManager, args, lang: str, logger):
    """Verify vault integrity"""
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
                print(f"\nAll checks passed - vault is healthy")
        else:
            print(f"Files: {results.get('file_count', 0)}")
            print(f"Header: {'OK' if results.get('header_ok') else 'FAILED'}")
            print(f"File Table: {'OK' if results.get('file_table_ok') else 'FAILED'}")
            
            if results.get('overall_ok'):
                print(f"\nQuick check passed - vault structure is valid")
            else:
                print(f"\nQuick check failed - vault structure issues detected")
                print("Run with --deep for detailed file verification")
    else:
        error_msg = results.get('message', 'Unknown verification error')
        print(f"ERROR: {error_msg}")
    
    print("=" * 40)


def _handle_storage(manager: VaultManager, args, lang: str, logger):
    """Show storage usage"""
    if not args.vault_name:
        print("Usage: obfutil vault storage <vault_name> --password/--key-file")
        return
        
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file for storage info")
        return

    storage_info = manager.check_vault_storage(args.vault_name, password, key)
    
    print(f"\n=== Storage: {args.vault_name} ===")
    print("=" * 45)
    if storage_info.get('status') == 'ok':
        total_mb = storage_info.get('total_size_mb', 0)
        used_mb = storage_info.get('used_space_mb', 0)
        free_mb = storage_info.get('free_space_mb', 0)
        usage_percent = storage_info.get('usage_percentage', 0)
        
        # Create a simple progress bar
        bar_len = 30
        filled = int(bar_len * usage_percent / 100)
        bar = '█' * filled + '░' * (bar_len - filled)
        
        print(f"Capacity:  {total_mb} MB")
        print(f"Used:      {used_mb} MB")
        print(f"Free:      {free_mb} MB")
        print(f"Usage:     {usage_percent:.1f}% [{bar}]")
        print(f"Files:     {storage_info.get('file_count', 0)}")
        
        if usage_percent > 90:
            print("\nWARNING: Vault is almost full!")
            print("   Consider creating a larger vault or removing old files")
    else:
        print(f"ERROR: {storage_info.get('message', 'Failed to get storage info')}")
    print("=" * 45)


def _handle_list(manager: VaultManager, args, lang: str, logger):
    """List all vaults"""
    vaults = manager.list_vaults()
    if not vaults:
        print("No vaults found.")
        print("\nCreate your first vault:")
        print("  obfutil vault create myvault --size 100 --password")
        return

    print("\n=== Vaults ===")
    print("=" * 55)
    print(f"{'Status':<8} {'Name':<18} {'Size':<10} {'Files':<8} {'Health'}")
    print("=" * 55)

    for vault in vaults:
        status = vault.get('status', 'UNKNOWN')
        # Color coding for status
        if status == 'ACTIVE':
            status_display = status
        elif status == 'MISSING':
            status_display = status
        else:
            status_display = status
            
        name = vault['name']
        size = f"{vault.get('size_mb', 0)}MB"
        files = vault.get('file_count', '?')
        health = vault.get('health', 'unknown')
        
        # Health indicator
        health_icon = 'OK' if health == 'accessible' else 'X' if health == 'locked' else '?'
        
        print(f"{status_display:<8} {name:<18} {size:<10} {files:<8} {health_icon} {health}")

    print(f"\nTotal: {len(vaults)} vault(s)")
    print("\nNote: File count and health require --password/--key-file")
    print("  OK = accessible, X = locked (needs authentication)")


def _handle_info(manager: VaultManager, args, lang: str, logger):
    """Show vault information"""
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
    print("=" * 55)
    print(f"Status: {info.get('status', 'UNKNOWN')}")
    
    # Date display with fallback
    created_at = info.get('created_at', 'Unknown')
    if created_at != 'Unknown':
        print(f"Created: {created_at}")
    else:
        try:
            vault_path = Path(manager.config[args.vault_name]['path'])
            if vault_path.exists():
                ctime = vault_path.stat().st_ctime
                created_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ctime))
                print(f"Created: {created_at} (from file system)")
        except:
            print(f"Created: {created_at}")
    
    print(f"Size:    {info.get('total_size_mb', 0)} MB")
    print(f"Used:    {info.get('used_space_mb', 0)} MB")
    print(f"Free:    {info.get('free_space_mb', 0)} MB")
    print(f"Files:   {info.get('file_count', 0)}")

    files = info.get('files_list', [])
    if files:
        print(f"\nFiles (first 20):")
        max_files = 20
        for i, file_path in enumerate(files[:max_files]):
            print(f"  - {file_path}")
        if len(files) > max_files:
            print(f"  ... and {len(files) - max_files} more files")
        print(f"\nUse 'obfutil vault stats {args.vault_name}' for detailed statistics")
    print("=" * 55)


def _handle_create(manager: VaultManager, args, lang: str, logger):
    """Create new vault"""
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
        
    print(f"Creating vault '{args.vault_name}' ({size}MB)...")
    success = manager.create_vault(args.vault_name, size, password, key)
    
    if success:
        print(f"Vault '{args.vault_name}' created successfully")
        print(f"\nNext steps:")
        print(f"  - Add files: obfutil vault add {args.vault_name} <file> --password")
        print(f"  - List files: obfutil vault preview {args.vault_name} --password")
        print(f"  - Check stats: obfutil vault stats {args.vault_name} --password")
    else:
        print(f"Failed to create vault '{args.vault_name}'")
        print("Possible reasons:")
        print("  - Vault already exists")
        print("  - Invalid password or key")
        print("  - Insufficient disk space")


def _handle_delete(manager: VaultManager, args, lang: str, logger):
    """Delete vault securely"""
    if not args.vault_name:
        print("Usage: obfutil vault delete <vault_name>")
        return
        
    if not manager.vault_exists(args.vault_name):
        print(f"ERROR: Vault '{args.vault_name}' not found!")
        return
        
    # Get vault info for warning
    info = manager.get_vault_info(args.vault_name)
    file_count = info.get('file_count', 'unknown')
    size_mb = info.get('total_size_mb', 0)
    
    print(f"\nWARNING: You are about to DELETE vault '{args.vault_name}'")
    if file_count != 'unknown':
        print(f"   This vault contains {file_count} file(s) totaling {size_mb} MB")
    print("   This action CANNOT be undone!")
    print()
    
    confirm = input(f"Type 'DELETE' to confirm deletion: ")
    if confirm == 'DELETE':
        print("Deleting vault...")
        success = manager.secure_vault_delete(args.vault_name)
        if success:
            print(f"Vault '{args.vault_name}' deleted successfully")
        else:
            print(f"Failed to delete vault")
    else:
        print("Deletion cancelled.")


def _handle_remove(manager: VaultManager, args, lang: str, logger):
    """Remove file from vault"""
    if not args.vault_name or not args.file_path:
        print("Usage: obfutil vault remove <vault_name> <internal_path> --password")
        return
    
    password, key = _get_auth_method(args, lang, logger)
    if password is None and key is None:
        print("ERROR: Specify --password or --key-file")
        return

    # Confirm removal
    print(f"File to remove: {args.file_path}")
    confirm = input(f"Remove from vault '{args.vault_name}'? [y/N]: ")
    if confirm.lower() != 'y':
        print("Removal cancelled.")
        return

    success = manager.remove_file_from_vault(args.vault_name, args.file_path, password, key)
    if success:
        print(f"File removed from vault '{args.vault_name}'")
    else:
        print(f"Failed to remove file")
        print("Check if file exists using 'obfutil vault preview'")


def _handle_debug_file(manager: VaultManager, args, lang: str, logger):
    """Debug file information"""
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
        print("Check log file for details: ~/.obfutil/logs/program.log")
    else:
        print(f"ERROR: Failed to debug file")


# ========== HELPER FUNCTIONS ==========

def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def _get_auth_method(args, lang, logger) -> Tuple[Optional[str], Optional[bytes]]:
    """
    Helper to get authentication method from args
    
    Returns:
        Tuple[Optional[str], Optional[bytes]]: (password, key)
    """
    password = None
    key = None
    
    if hasattr(args, 'key_file') and args.key_file:
        try:
            key = load_key_from_file(DEFAULT_KEY_PATH)
            logger.debug("Using key file for authentication")
        except FileNotFoundError:
            print(f"ERROR: Key file not found at {DEFAULT_KEY_PATH}")
            print("Generate a key first with: obfutil --gen-key")
            print()
            return None, None
        except Exception as e:
            print(f"ERROR: Failed to load key file: {e}")
            return None, None
    elif hasattr(args, 'password') and args.password:
        try:
            password = input_password(get_translation(lang, "password_prompt"))
            logger.debug("Using password for authentication")
        except Exception as e:
            print(f"ERROR: Failed to read password: {e}")
            return None, None
    
    return password, key