#!/usr/bin/env python3
"""
SwiftFS Command-Line Interface (CLI)
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Ensure standard output can print safely on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to sys.path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

try:
    import python as swiftfs_pkg
    from python import (
        BatchProcessor,
        HashAlgorithm,
        HashOptions,
        ScanOptions,
        Scanner,
        Hasher,
    )
    from python.formatter import format_bytes, format_duration, print_terminal_report, report_to_dict
except (ImportError, AttributeError):
    try:
        from _swiftfs_core import (  # type: ignore
            BatchProcessor,
            HashAlgorithm,
            HashOptions,
            ScanOptions,
            Scanner,
            Hasher,
        )
        from formatter import format_bytes, format_duration, print_terminal_report, report_to_dict  # type: ignore
    except ImportError as e:
        print(f"[Error] Failed to load SwiftFS C++ native extension: {e}")
        print("Please build the extension first using CMake or: pip install -e .")
        sys.exit(1)


def parse_size_str(size_str: str) -> int:
    """Parses a size string like '10MB', '500KB', '1GB' into bytes."""
    size_str = size_str.strip().upper()
    multipliers = {
        "B": 1,
        "KB": 1024,
        "K": 1024,
        "MB": 1024**2,
        "M": 1024**2,
        "GB": 1024**3,
        "G": 1024**3,
        "TB": 1024**4,
        "T": 1024**4,
    }
    for unit, mult in multipliers.items():
        if size_str.endswith(unit):
            num = size_str[: -len(unit)].strip()
            return int(float(num) * mult)
    return int(size_str)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="swiftfs",
        description="SwiftFS - Ultra-fast multi-threaded filesystem scanner, duplicate finder, and disk analyzer.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Target root directory to scan (default: current directory)")
    parser.add_argument("-t", "--threads", type=int, default=0, help="Number of worker threads (0 = auto-detect CPU cores)")
    parser.add_argument("-a", "--algorithm", choices=["xxh64", "sha256", "crc32", "fnv1a", "md5"], default="xxh64", help="Hashing algorithm (default: xxh64)")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick mode: hashes only the initial 4KB prefix of files")
    parser.add_argument("-d", "--max-depth", type=int, default=-1, help="Maximum recursion depth (-1 = unlimited)")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files and folders in analysis")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symbolic directory links and NTFS junctions")
    parser.add_argument("--no-default-ignores", action="store_true", help="Disable default ignore patterns (.git, node_modules, build, etc.)")
    parser.add_argument("--min-size", type=str, default=None, help="Filter files larger than or equal to size (e.g. 100KB, 5MB)")
    parser.add_argument("--max-size", type=str, default=None, help="Filter files smaller than or equal to size (e.g. 1GB)")
    parser.add_argument("--ext", type=str, default=None, help="Comma-separated file extensions to include (e.g. 'cpp,h,py')")
    parser.add_argument("--exclude-ext", type=str, default=None, help="Comma-separated file extensions to ignore")
    parser.add_argument("--ignore", type=str, default=None, help="Comma-separated directory or path patterns to skip (e.g. '.git,node_modules,build')")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("-o", "--export", type=str, default=None, help="Export analysis report to a JSON file path")
    parser.add_argument("--no-duplicates", action="store_true", help="Hide duplicates section in terminal output")
    parser.add_argument("--no-extensions", action="store_true", help="Hide extension breakdown section")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"[Error] Path does not exist: {target_path}", file=sys.stderr)
        sys.exit(1)

    # Configure ScanOptions
    scan_opts = ScanOptions()
    scan_opts.recursive = True
    scan_opts.max_depth = args.max_depth
    scan_opts.include_hidden = args.include_hidden
    scan_opts.follow_symlinks = args.follow_symlinks

    if args.min_size:
        scan_opts.min_file_size = parse_size_str(args.min_size)
    if args.max_size:
        scan_opts.max_file_size = parse_size_str(args.max_size)
    if args.ext:
        scan_opts.include_extensions = [e.strip() for e in args.ext.split(",") if e.strip()]
    if args.exclude_ext:
        scan_opts.exclude_extensions = [e.strip() for e in args.exclude_ext.split(",") if e.strip()]
    if args.ignore:
        scan_opts.exclude_patterns = [p.strip() for p in args.ignore.split(",") if p.strip()]
    elif not args.no_default_ignores:
        # Default smart ignores for project folders
        scan_opts.exclude_patterns = [".git", "node_modules", ".vs", "__pycache__", ".idea"]
    else:
        scan_opts.exclude_patterns = []

    # Configure HashOptions
    algo_map = {
        "xxh64": HashAlgorithm.XXH64,
        "sha256": HashAlgorithm.SHA256,
        "crc32": HashAlgorithm.CRC32,
        "fnv1a": HashAlgorithm.FNV1A_64,
        "md5": HashAlgorithm.MD5,
    }
    hash_opts = HashOptions()
    hash_opts.algorithm = algo_map.get(args.algorithm, HashAlgorithm.XXH64)
    hash_opts.quick_mode = args.quick

    # Initialize Processor
    processor = BatchProcessor(num_threads=args.threads, algorithm=hash_opts.algorithm)

    if not args.json:
        print(f"[*] SwiftFS scanning: {target_path}")
        print(f"[*] Threads: {processor.num_threads} | Hash Algorithm: {args.algorithm.upper()}{' (Quick Prefix)' if args.quick else ''}")

    # Progress callback for interactive terminal
    last_print = 0.0

    def on_progress(update) -> None:
        nonlocal last_print
        now = time.time()
        if not args.json and (now - last_print > 0.1 or update.completed_items == update.total_items):
            pct = (update.completed_items / update.total_items * 100.0) if update.total_items > 0 else 100.0
            filename = (update.current_file[:25] + "...") if len(update.current_file) > 28 else update.current_file
            sys.stdout.write(f"\r[>] Processing [{pct:5.1f}%] ({update.completed_items}/{update.total_items}) | {format_bytes(update.bytes_processed)} | {filename:<28}")
            sys.stdout.flush()
            last_print = now

    # Run processing
    report = processor.process_directory(
        target_path,
        scan_opts=scan_opts,
        hash_opts=hash_opts,
        progress_cb=on_progress if not args.json else None,
    )

    if not args.json:
        # Clear progress line
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    # Output Formatting
    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print_terminal_report(
            report,
            show_duplicates=not args.no_duplicates,
            show_extensions=not args.no_extensions,
            show_largest=True,
        )

    # Optional export to JSON file
    if args.export:
        export_path = Path(args.export).resolve()
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(report_to_dict(report), f, indent=2)
        if not args.json:
            print(f"[+] Report exported to: {export_path}")


if __name__ == "__main__":
    main()
