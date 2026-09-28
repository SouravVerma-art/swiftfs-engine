#include "scanner.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <deque>
#include <iostream>
#include <regex>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace swiftfs {

namespace {

std::string path_to_utf8(const fs::path& p) {
#if defined(_WIN32)
    const std::wstring ws = p.native();
    if (ws.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return {};
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), str.data(), size_needed, nullptr, nullptr);
    return str;
#else
    return p.string();
#endif
}

fs::path utf8_to_path(const std::string& str) {
#if defined(_WIN32)
    if (str.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring ws(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), ws.data(), wlen);
    return fs::path(ws);
#else
    return fs::path(str);
#endif
}

std::string to_lower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return str;
}

int64_t file_time_to_epoch(fs::file_time_type ftime) {
    try {
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        return std::chrono::duration_cast<std::chrono::seconds>(sctp.time_since_epoch()).count();
    } catch (...) {
        return 0;
    }
}

} // namespace

Scanner::Scanner(ScanOptions options) : options_(std::move(options)) {
    for (auto& ext : options_.include_extensions) {
        if (!ext.empty() && ext.front() == '.') {
            ext = ext.substr(1);
        }
        ext = to_lower(ext);
    }
    for (auto& ext : options_.exclude_extensions) {
        if (!ext.empty() && ext.front() == '.') {
            ext = ext.substr(1);
        }
        ext = to_lower(ext);
    }
}

bool Scanner::is_hidden(const fs::path& path) const {
    std::string filename = path_to_utf8(path.filename());
    if (!filename.empty() && filename.front() == '.' && filename != "." && filename != "..") {
        return true;
    }

#if defined(_WIN32)
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) {
        return true;
    }
#endif

    return false;
}

bool Scanner::should_include_extension(const std::string& ext) const {
    std::string lower_ext = to_lower(ext);
    if (!lower_ext.empty() && lower_ext.front() == '.') {
        lower_ext = lower_ext.substr(1);
    }

    if (!options_.exclude_extensions.empty()) {
        for (const auto& excl : options_.exclude_extensions) {
            if (lower_ext == excl) {
                return false;
            }
        }
    }

    if (!options_.include_extensions.empty()) {
        for (const auto& incl : options_.include_extensions) {
            if (lower_ext == incl) {
                return true;
            }
        }
        return false;
    }

    return true;
}

bool Scanner::is_excluded_by_pattern(const std::string& path_str) const {
    if (options_.exclude_patterns.empty()) {
        return false;
    }

    fs::path p = utf8_to_path(path_str);
    std::string filename = to_lower(path_to_utf8(p.filename()));

    for (const auto& raw_pattern : options_.exclude_patterns) {
        if (raw_pattern.empty()) continue;
        std::string pattern = to_lower(raw_pattern);

        // Exact folder/file name match (e.g., ".git", "node_modules")
        if (filename == pattern) {
            return true;
        }

        // Exact path component match
        std::string sep1 = "/" + pattern + "/";
        std::string sep2 = "\\" + pattern + "\\";
        std::string lower_path = to_lower(path_str);
        if (lower_path.find(sep1) != std::string::npos ||
            lower_path.find(sep2) != std::string::npos) {
            return true;
        }

        try {
            std::regex reg(pattern, std::regex_constants::icase);
            if (std::regex_search(path_str, reg)) {
                return true;
            }
        } catch (...) {
        }
    }
    return false;
}

bool Scanner::matches_filters(const fs::directory_entry& entry, uint64_t size) const {
    const auto& p = entry.path();
    std::string path_str = path_to_utf8(p);

    if (is_excluded_by_pattern(path_str)) {
        return false;
    }

    if (!options_.include_hidden && is_hidden(p)) {
        return false;
    }

    std::error_code ec;
    if (entry.is_regular_file(ec)) {
        if (size < options_.min_file_size || size > options_.max_file_size) {
            return false;
        }

        std::string ext = p.has_extension() ? path_to_utf8(p.extension()) : "";
        if (!should_include_extension(ext)) {
            return false;
        }
    }

    return true;
}

ScanStats Scanner::scan_streaming(const std::string& root_path,
                                  const std::function<void(const FileEntry&)>& on_entry,
                                  const std::function<void(const std::string&)>& on_error) {
    ScanStats stats;
    auto start_time = std::chrono::steady_clock::now();

    std::error_code ec;
    fs::path root = utf8_to_path(root_path);

    if (!fs::exists(root, ec) || ec) {
        if (on_error) {
            on_error("Root path does not exist or is inaccessible: " + root_path);
        }
        stats.total_errors++;
        return stats;
    }

    fs::directory_options dir_options = fs::directory_options::skip_permission_denied;
    if (options_.follow_symlinks) {
        dir_options |= fs::directory_options::follow_directory_symlink;
    }

    struct QueueItem {
        fs::path dir_path;
        int depth;
    };

    std::deque<QueueItem> dir_queue;
    dir_queue.push_back({root, 0});

    while (!dir_queue.empty()) {
        QueueItem current = std::move(dir_queue.front());
        dir_queue.pop_front();

        if (options_.max_depth >= 0 && current.depth > options_.max_depth) {
            continue;
        }

        ec.clear();
        auto it = fs::directory_iterator(current.dir_path, dir_options, ec);
        if (ec) {
            if (on_error) on_error(ec.message() + ": " + path_to_utf8(current.dir_path));
            stats.total_errors++;
            continue;
        }

        auto end = fs::directory_iterator();
        while (it != end) {
            ec.clear();
            const auto& entry = *it;
            const auto& p = entry.path();

            bool is_dir = entry.is_directory(ec);
            if (ec) {
                stats.total_errors++;
                ec.clear();
                it.increment(ec);
                continue;
            }

            bool is_sym = entry.is_symlink(ec);
            ec.clear();

            std::string path_utf8 = path_to_utf8(p);

            // Skip recursion into excluded / hidden directories
            if (is_dir) {
                if (is_excluded_by_pattern(path_utf8) || (!options_.include_hidden && is_hidden(p))) {
                    it.increment(ec);
                    continue;
                }
            }

            uint64_t file_size = 0;
            bool is_reg = entry.is_regular_file(ec);
            if (ec) {
                is_reg = false;
                ec.clear();
            }

            if (is_reg) {
                file_size = entry.file_size(ec);
                if (ec) {
                    file_size = 0;
                    ec.clear();
                }
            }

            if (matches_filters(entry, file_size)) {
                FileEntry fe;
                fe.path = path_utf8;
                fe.filename = path_to_utf8(p.filename());
                fe.extension = p.has_extension() ? path_to_utf8(p.extension()) : "";
                fe.size_bytes = file_size;
                fe.is_directory = is_dir;
                fe.is_regular_file = is_reg;
                fe.is_symlink = is_sym;
                fe.is_hidden = is_hidden(p);
                fe.last_modified_epoch = file_time_to_epoch(entry.last_write_time(ec));

                if (fe.is_directory) {
                    stats.total_directories++;
                } else if (fe.is_regular_file) {
                    stats.total_files++;
                    stats.total_bytes += fe.size_bytes;
                }

                if (on_entry) {
                    on_entry(fe);
                }
            }

            if (is_dir && options_.recursive) {
                if (options_.follow_symlinks || !is_sym) {
                    dir_queue.push_back({p, current.depth + 1});
                }
            }

            it.increment(ec);
            if (ec) {
                stats.total_errors++;
                ec.clear();
            }
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    stats.elapsed_time_seconds = std::chrono::duration<double>(end_time - start_time).count();
    return stats;
}

ScanResult Scanner::scan(const std::string& root_path) {
    ScanResult result;
    result.stats = scan_streaming(
        root_path,
        [&result](const FileEntry& entry) {
            result.entries.push_back(entry);
        },
        [&result](const std::string& err) {
            result.errors.push_back(err);
        }
    );
    return result;
}

} // namespace swiftfs
