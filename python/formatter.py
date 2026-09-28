"""
Output formatting, ANSI styling, and reporting utilities for SwiftFS.
"""

import json
import sys
from typing import Any, Dict, List

# Ensure stdout handles UTF-8 on Windows consoles without throwing UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def format_bytes(size_bytes: int) -> str:
    """Formats bytes into human-readable unit string."""
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


def format_duration(seconds: float) -> str:
    """Formats seconds into human-readable duration."""
    if seconds < 0.001:
        return f"{seconds * 1000000:.1f} us"
    elif seconds < 1.0:
        return f"{seconds * 1000:.2f} ms"
    elif seconds < 60.0:
        return f"{seconds:.2f} s"
    else:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.1f}s"


def report_to_dict(report: Any) -> Dict[str, Any]:
    """Converts a C++ ProcessingReport into a serializable Python dictionary."""
    return {
        "summary": {
            "total_files": getattr(report.scan_stats, "total_files", 0),
            "total_directories": getattr(report.scan_stats, "total_directories", 0),
            "total_bytes": getattr(report.scan_stats, "total_bytes", 0),
            "total_bytes_formatted": format_bytes(getattr(report.scan_stats, "total_bytes", 0)),
            "files_hashed": getattr(report, "files_hashed", 0),
            "total_hashed_bytes": getattr(report, "total_hashed_bytes", 0),
            "total_hashed_bytes_formatted": format_bytes(getattr(report, "total_hashed_bytes", 0)),
            "total_errors": getattr(report.scan_stats, "total_errors", 0),
            "scan_duration_seconds": getattr(report.scan_stats, "elapsed_time_seconds", 0.0),
            "total_duration_seconds": getattr(report, "processing_duration_seconds", 0.0),
            "total_duration_formatted": format_duration(getattr(report, "processing_duration_seconds", 0.0)),
        },
        "duplicates": {
            "group_count": len(getattr(report, "duplicate_groups", [])),
            "duplicate_files_count": getattr(report, "total_duplicate_files", 0),
            "wasted_bytes": getattr(report, "total_wasted_bytes", 0),
            "wasted_bytes_formatted": format_bytes(getattr(report, "total_wasted_bytes", 0)),
            "groups": [
                {
                    "hash": g.hash,
                    "file_size": g.file_size,
                    "file_size_formatted": format_bytes(g.file_size),
                    "file_paths": list(g.file_paths),
                    "wasted_bytes": g.wasted_bytes,
                    "wasted_bytes_formatted": format_bytes(g.wasted_bytes),
                }
                for g in getattr(report, "duplicate_groups", [])
            ],
        },
        "extensions": [
            {
                "extension": ext.extension,
                "file_count": ext.file_count,
                "total_bytes": ext.total_bytes,
                "total_bytes_formatted": format_bytes(ext.total_bytes),
                "percentage": round(ext.percentage_of_total_bytes, 2),
            }
            for ext in getattr(report, "extension_summary", [])
        ],
        "largest_files": [
            {
                "path": f.entry.path,
                "size_bytes": f.entry.size_bytes,
                "size_formatted": format_bytes(f.entry.size_bytes),
                "hash": f.hash.hex_digest if hasattr(f, "hash") else "",
            }
            for f in getattr(report, "largest_files", [])
        ],
        "errors": list(getattr(report, "errors", [])),
    }


def print_terminal_report(report: Any, show_duplicates: bool = True, show_extensions: bool = True, show_largest: bool = True) -> None:
    """Prints a clean, cross-platform terminal dashboard summary."""
    stats = report.scan_stats
    duration_str = format_duration(report.processing_duration_seconds)
    total_bytes_str = format_bytes(stats.total_bytes)
    wasted_bytes_str = format_bytes(report.total_wasted_bytes)

    print("\n" + "=" * 70)
    print("                      SWIFTFS ANALYSIS REPORT")
    print("=" * 70)

    print(f"\n[+] Files Discovered : {stats.total_files:,}")
    print(f"[+] Directories      : {stats.total_directories:,}")
    print(f"[+] Total Disk Size  : {total_bytes_str}")
    print(f"[+] Files Hashed     : {report.files_hashed:,}")
    print(f"[+] Total Duration   : {duration_str}")
    if stats.total_errors > 0:
        print(f"[!] Errors Encountered: {stats.total_errors:,}")

    if show_duplicates:
        print("\n" + "-" * 70)
        print(f"DUPLICATE FILES SUMMARY (Wasted Space: {wasted_bytes_str})")
        print("-" * 70)
        if not report.duplicate_groups:
            print("  No duplicate files detected.")
        else:
            for idx, g in enumerate(report.duplicate_groups[:10], 1):
                print(f"\n  [Group #{idx}] Hash: {g.hash[:16]}... | Size: {format_bytes(g.file_size)} each | Wasted: {format_bytes(g.wasted_bytes)}")
                for p in g.file_paths:
                    print(f"    - {p}")
            if len(report.duplicate_groups) > 10:
                print(f"\n  ... and {len(report.duplicate_groups) - 10} more duplicate groups.")

    if show_extensions and report.extension_summary:
        print("\n" + "-" * 70)
        print("TOP EXTENSION BREAKDOWN")
        print("-" * 70)
        print(f"  {'Extension':<15} {'Files':<10} {'Total Size':<15} {'Percentage'}")
        print(f"  {'-'*13:<15} {'-'*8:<10} {'-'*13:<15} {'-'*10}")
        for ext in report.extension_summary[:8]:
            ext_name = ext.extension if ext.extension else "(none)"
            print(f"  {ext_name:<15} {ext.file_count:<10} {format_bytes(ext.total_bytes):<15} {ext.percentage_of_total_bytes:.1f}%")

    if show_largest and report.largest_files:
        print("\n" + "-" * 70)
        print("LARGEST FILES")
        print("-" * 70)
        for idx, f in enumerate(report.largest_files[:5], 1):
            print(f"  {idx}. {format_bytes(f.entry.size_bytes):<10} -> {f.entry.path}")

    print("\n" + "=" * 70 + "\n")
