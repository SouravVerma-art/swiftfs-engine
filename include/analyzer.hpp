#pragma once

#include "scanner.hpp"
#include "hasher.hpp"
#include "processor.hpp"

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>

namespace swiftfs {

/**
 * @brief Standalone filesystem analytics and duplicate detection engine.
 */
class Analyzer {
public:
    /**
     * @brief Identifies groups of duplicate files from processed file entries.
     */
    static std::vector<DuplicateGroup> find_duplicates(const std::vector<ProcessedFile>& files);

    /**
     * @brief Computes file extension distribution and storage breakdown.
     */
    static std::vector<ExtensionStats> summarize_extensions(const std::vector<FileEntry>& entries);

    /**
     * @brief Retrieves the top N largest files sorted in descending order of size.
     */
    static std::vector<ProcessedFile> find_largest_files(const std::vector<ProcessedFile>& files, size_t top_n = 10);

    /**
     * @brief Compiles a complete ProcessingReport from scan entries and hashed results.
     */
    static ProcessingReport generate_report(const ScanStats& scan_stats,
                                           const std::vector<ProcessedFile>& processed_files,
                                           double total_duration_seconds,
                                           const std::vector<std::string>& errors = {});
};

} // namespace swiftfs
