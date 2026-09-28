"""
SwiftFS - High-Performance Filesystem Scanner and Analysis Engine
"""

import sys
from pathlib import Path

# Add potential build/output directories to sys.path so the compiled C-extension
# (.pyd on Windows / .so on Linux/macOS) is automatically discovered in both
# single-config and multi-config (Release/Debug) builds.
_current_dir = Path(__file__).resolve().parent
_possible_paths = [
    _current_dir,
    _current_dir / "Release",
    _current_dir / "Debug",
    _current_dir.parent / "build",
    _current_dir.parent / "build" / "Release",
    _current_dir.parent / "build" / "Debug",
]

for p in _possible_paths:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Attempt importing compiled C++ native module
try:
    from _swiftfs_core import (
        FileEntry,
        ScanOptions,
        ScanStats,
        ScanResult,
        Scanner,
        HashAlgorithm,
        HashResult,
        HashOptions,
        Hasher,
        ProcessedFile,
        DuplicateGroup,
        ExtensionStats,
        ProcessingReport,
        ProgressUpdate,
        BatchProcessor,
        Analyzer,
    )
except ImportError as e:
    pass

__version__ = "0.1.0"
