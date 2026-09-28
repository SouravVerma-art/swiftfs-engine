#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <chrono>
#include <filesystem>
#include <optional>
#include <limits>

namespace swiftfs {

namespace fs = std::filesystem;

/**
 * @brief Represents metadata of a single discovered filesystem entry.
 */
struct FileEntry {
    std::string path;
    std::string filename;
    std::string extension;
    uint64_t size_bytes{0};
    int64_t last_modified_epoch{0}; // Seconds since UNIX epoch
    bool is_directory{false};
    bool is_regular_file{false};
    bool is_symlink{false};
    bool is_hidden{false};
};

/**
 * @brief Configuration options for scanning directories.
 */
struct ScanOptions {
    bool recursive{true};
    int max_depth{-1}; // -1 means unlimited depth
    bool follow_symlinks{false};
    bool include_hidden{false};
    uint64_t min_file_size{0};
    uint64_t max_file_size{std::numeric_limits<uint64_t>::max()};

    // Extensions without leading dot, e.g. ["cpp", "py", "txt"]
    std::vector<std::string> include_extensions{};
    std::vector<std::string> exclude_extensions{};

    // Glob/regex directory or filename patterns to ignore (e.g., [".git", "node_modules", "build"])
    std::vector<std::string> exclude_patterns{};
};

/**
 * @brief Aggregated summary and performance metrics of a scan run.
 */
struct ScanStats {
    size_t total_files{0};
    size_t total_directories{0};
    uint64_t total_bytes{0};
    size_t total_errors{0};
    double elapsed_time_seconds{0.0};
};

/**
 * @brief Complete result containing discovered entries and scan telemetry.
 */
struct ScanResult {
    std::vector<FileEntry> entries;
    ScanStats stats;
    std::vector<std::string> errors;
};

/**
 * @brief High-performance filesystem scanner.
 */
class Scanner {
public:
    explicit Scanner(ScanOptions options = {});

    /**
     * @brief Recursively scans the directory starting from root_path and returns all entries.
     */
    ScanResult scan(const std::string& root_path);

    /**
     * @brief Streams entries matching the scan options to a callback for zero-allocation streaming.
     */
    ScanStats scan_streaming(const std::string& root_path,
                             const std::function<void(const FileEntry&)>& on_entry,
                             const std::function<void(const std::string&)>& on_error = nullptr);

    void set_options(const ScanOptions& options) { options_ = options; }
    const ScanOptions& get_options() const { return options_; }

private:
    ScanOptions options_;

    bool is_hidden(const fs::path& path) const;
    bool should_include_extension(const std::string& ext) const;
    bool is_excluded_by_pattern(const std::string& path_str) const;
    bool matches_filters(const fs::directory_entry& entry, uint64_t size) const;
};

} // namespace swiftfs
