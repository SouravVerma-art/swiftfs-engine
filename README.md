# SwiftFS ⚡

**SwiftFS** is an ultra-fast, multi-threaded filesystem scanner, duplicate file detector, and disk usage analyzer powered by a modern **C++20** engine with first-class **Python 3** bindings and CLI.

---

## 🏗️ Architecture

```
SwiftFS/
├── include/                  # Public C++20 Header API
│   ├── scanner.hpp           # Directory scanner & entry models
│   ├── hasher.hpp            # Multi-algorithm stream hasher (XXH64, SHA256, CRC32, FNV-1a)
│   ├── processor.hpp         # ThreadPool & BatchProcessor pipeline
│   ├── analyzer.hpp          # Duplicate clustering & disk breakdown analytics
│   └── swiftfs.hpp           # Master umbrella include
├── cpp/                      # C++ Engine Implementations
│   ├── scanner.cpp           # Fast directory traversal & filtering
│   ├── hasher.cpp            # Hash implementations & stream buffering
│   ├── processor.cpp         # Worker pool & parallel batch dispatcher
│   └── analyzer.cpp          # Duplicate detection & reporting
├── bindings/                 # Pybind11 Native Interop Bridge
│   └── bindings.cpp          # Python C-extension definitions (GIL release)
├── python/                   # Python Package & CLI
│   ├── __init__.py           # Package exports
│   ├── cli.py                # Command-line interface
│   └── formatter.py          # Dashboard styling, tables & JSON exports
├── tests/                    # C++ and Python Test Suites
│   ├── main_test.cpp         # Standalone C++ unit test runner
│   └── test_swiftfs.py       # Python unit tests
├── CMakeLists.txt            # CMake build configuration
└── pyproject.toml            # Python package configuration
```

---

## 🚀 Building & Installing

### 1. Build via CMake (C++ & Native Extension)
```powershell
# Configure build directory
cmake -B build -S .

# Compile in Release mode
cmake --build build --config Release
```

### 2. Install Python Package Locally
```powershell
pip install -e .
```

---

## 💻 CLI Usage

Scan a directory:
```powershell
python python/cli.py C:\path\to\scan
```

### Options & Flags

| Flag | Description |
| :--- | :--- |
| `-t, --threads <N>` | Number of concurrent worker threads (default: CPU cores) |
| `-a, --algorithm <algo>` | Hashing algorithm (`xxh64`, `sha256`, `crc32`, `fnv1a`) |
| `-q, --quick` | Fast mode: samples first 4KB prefix for instant filtering |
| `-d, --max-depth <N>` | Maximum directory traversal depth |
| `--min-size <size>` | Filter minimum file size (e.g. `100KB`, `10MB`, `1GB`) |
| `--max-size <size>` | Filter maximum file size |
| `--ext <exts>` | Whitelist extensions (e.g. `cpp,py,txt`) |
| `--ignore <patterns>` | Ignore paths/folders (e.g. `node_modules,.git,build`) |
| `-j, --json` | Output results as machine-readable JSON |
| `-o, --export <file>` | Export report directly to a JSON file |

---

## 🐍 Python API Example

```python
import swiftfs

# Configure scan
scan_opts = swiftfs.ScanOptions()
scan_opts.recursive = True
scan_opts.exclude_patterns = [".git", "node_modules"]

# Configure hasher
hash_opts = swiftfs.HashOptions()
hash_opts.algorithm = swiftfs.HashAlgorithm.XXH64

# Process directory
processor = swiftfs.BatchProcessor(num_threads=8)
report = processor.process_directory("C:/my_folder", scan_opts, hash_opts)

print(f"Total Files: {report.scan_stats.total_files}")
print(f"Wasted Duplicate Space: {report.total_wasted_bytes} bytes")
for group in report.duplicate_groups:
    print(f"Duplicate files: {group.file_paths}")
```
