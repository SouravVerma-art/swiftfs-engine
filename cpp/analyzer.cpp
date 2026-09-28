#include "analyzer.hpp"

#include <algorithm>
#include <unordered_map>

namespace swiftfs {

std::vector<DuplicateGroup> Analyzer::find_duplicates(const std::vector<ProcessedFile>& files) {
    // Map hash string to list of file indices
    std::unordered_map<std::string, std::vector<size_t>> hash_map;
    hash_map.reserve(files.size());

    for (size_t i = 0; i < files.size(); ++i) {
        const auto& pf = files[i];
        if (pf.hash.success && !pf.hash.hex_digest.empty() && pf.entry.is_regular_file) {
            hash_map[pf.hash.hex_digest].push_back(i);
        }
    }

    std::vector<DuplicateGroup> duplicates;

    for (auto& [digest, indices] : hash_map) {
        if (indices.size() > 1) {
            DuplicateGroup group;
            group.hash = digest;
            group.file_size = files[indices[0]].entry.size_bytes;
            group.file_paths.reserve(indices.size());

            for (size_t idx : indices) {
                group.file_paths.push_back(files[idx].entry.path);
            }

            group.wasted_bytes = group.file_size * (indices.size() - 1);
            duplicates.push_back(std::move(group));
        }
    }

    // Sort duplicates by wasted bytes descending
    std::sort(duplicates.begin(), duplicates.end(), [](const DuplicateGroup& a, const DuplicateGroup& b) {
        return a.wasted_bytes > b.wasted_bytes;
    });

    return duplicates;
}

std::vector<ExtensionStats> Analyzer::summarize_extensions(const std::vector<FileEntry>& entries) {
    std::unordered_map<std::string, std::pair<size_t, uint64_t>> ext_map;
    uint64_t grand_total_bytes = 0;

    for (const auto& entry : entries) {
        if (!entry.is_regular_file) continue;

        std::string ext = entry.extension;
        if (ext.empty()) {
            ext = "(no extension)";
        } else if (ext.front() == '.') {
            ext = ext.substr(1);
        }

        // Convert extension to lowercase for aggregation
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        ext_map[ext].first++;
        ext_map[ext].second += entry.size_bytes;
        grand_total_bytes += entry.size_bytes;
    }

    std::vector<ExtensionStats> results;
    results.reserve(ext_map.size());

    for (const auto& [ext, stats] : ext_map) {
        ExtensionStats es;
        es.extension = ext;
        es.file_count = stats.first;
        es.total_bytes = stats.second;
        es.percentage_of_total_bytes = (grand_total_bytes > 0)
            ? (static_cast<double>(stats.second) / static_cast<double>(grand_total_bytes)) * 100.0
            : 0.0;
        results.push_back(es);
    }

    // Sort by total bytes descending
    std::sort(results.begin(), results.end(), [](const ExtensionStats& a, const ExtensionStats& b) {
        return a.total_bytes > b.total_bytes;
    });

    return results;
}

std::vector<ProcessedFile> Analyzer::find_largest_files(const std::vector<ProcessedFile>& files, size_t top_n) {
    std::vector<ProcessedFile> sorted = files;
    std::sort(sorted.begin(), sorted.end(), [](const ProcessedFile& a, const ProcessedFile& b) {
        return a.entry.size_bytes > b.entry.size_bytes;
    });

    if (sorted.size() > top_n) {
        sorted.resize(top_n);
    }
    return sorted;
}

ProcessingReport Analyzer::generate_report(const ScanStats& scan_stats,
                                           const std::vector<ProcessedFile>& processed_files,
                                           double total_duration_seconds,
                                           const std::vector<std::string>& errors) {
    ProcessingReport report;
    report.scan_stats = scan_stats;
    report.files_hashed = processed_files.size();
    report.processing_duration_seconds = total_duration_seconds;
    report.errors = errors;

    // Aggregate hashed bytes
    for (const auto& pf : processed_files) {
        report.total_hashed_bytes += pf.hash.bytes_hashed;
    }

    // Duplicates
    report.duplicate_groups = find_duplicates(processed_files);
    for (const auto& group : report.duplicate_groups) {
        report.total_duplicate_files += group.file_paths.size();
        report.total_wasted_bytes += group.wasted_bytes;
    }

    // Extract entries for extension analysis
    std::vector<FileEntry> entries;
    entries.reserve(processed_files.size());
    for (const auto& pf : processed_files) {
        entries.push_back(pf.entry);
    }
    report.extension_summary = summarize_extensions(entries);

    // Top 10 largest files
    report.largest_files = find_largest_files(processed_files, 10);

    return report;
}

} // namespace swiftfs
