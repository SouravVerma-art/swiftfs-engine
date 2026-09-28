#pragma once

#include "scanner.hpp"
#include "hasher.hpp"

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <future>
#include <atomic>

namespace swiftfs {

/**
 * @brief Represents a file with both metadata and computed content hash.
 */
struct ProcessedFile {
    FileEntry entry;
    HashResult hash;
    bool is_duplicate{false};
};

/**
 * @brief Represents a cluster of duplicate files sharing the same content hash.
 */
struct DuplicateGroup {
    std::string hash;
    uint64_t file_size{0};
    std::vector<std::string> file_paths;
    uint64_t wasted_bytes{0}; // file_size * (file_paths.size() - 1)
};

/**
 * @brief Aggregated file extension breakdown statistics.
 */
struct ExtensionStats {
    std::string extension;
    size_t file_count{0};
    uint64_t total_bytes{0};
    double percentage_of_total_bytes{0.0};
};

/**
 * @brief Comprehensive analysis and processing report.
 */
struct ProcessingReport {
    ScanStats scan_stats;
    size_t files_hashed{0};
    uint64_t total_hashed_bytes{0};
    double processing_duration_seconds{0.0};
    
    // Duplicate Analysis
    std::vector<DuplicateGroup> duplicate_groups;
    size_t total_duplicate_files{0};
    uint64_t total_wasted_bytes{0};
    
    // Size & Extension Analysis
    std::vector<ExtensionStats> extension_summary;
    std::vector<ProcessedFile> largest_files; // Top N largest files
    
    std::vector<std::string> errors;
};

/**
 * @brief High-performance thread pool for concurrent CPU and I/O batch jobs.
 */
class ThreadPool {
public:
    explicit ThreadPool(size_t thread_count = 0);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args) 
        -> std::future<typename std::invoke_result<F, Args...>::type> {
        using return_type = typename std::invoke_result<F, Args...>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        condition_.notify_one();
        return res;
    }

    size_t thread_count() const { return workers_.size(); }
    void wait_idle();

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::condition_variable idle_condition_;
    std::atomic<size_t> active_tasks_{0};
    std::atomic<bool> stop_{false};
};

/**
 * @brief Progress update notification payload for streaming progress bars.
 */
struct ProgressUpdate {
    size_t completed_items{0};
    size_t total_items{0};
    uint64_t bytes_processed{0};
    std::string current_file;
};

using ProgressCallback = std::function<void(const ProgressUpdate&)>;

/**
 * @brief Multi-threaded batch processor and filesystem analyzer.
 */
class BatchProcessor {
public:
    BatchProcessor(size_t num_threads = 0, HashAlgorithm algorithm = HashAlgorithm::XXH64);

    /**
     * @brief Executes complete pipeline: directory scanning, concurrent hashing, duplicate identification, and statistical reporting.
     */
    ProcessingReport process_directory(const std::string& root_path, 
                                       const ScanOptions& scan_opts = {}, 
                                       const HashOptions& hash_opts = {},
                                       ProgressCallback progress_cb = nullptr);

    /**
     * @brief Concurrently hashes a pre-scanned list of file entries.
     */
    std::vector<ProcessedFile> hash_files_parallel(const std::vector<FileEntry>& files,
                                                  const HashOptions& hash_opts = {},
                                                  ProgressCallback progress_cb = nullptr);

    /**
     * @brief Performs duplicate detection analysis on hashed entries.
     */
    static std::vector<DuplicateGroup> analyze_duplicates(const std::vector<ProcessedFile>& processed_files);

    /**
     * @brief Aggregates file extension distribution and disk usage.
     */
    static std::vector<ExtensionStats> analyze_extensions(const std::vector<FileEntry>& entries);

    /**
     * @brief Extracts top N largest files.
     */
    static std::vector<ProcessedFile> get_largest_files(const std::vector<ProcessedFile>& processed_files, size_t top_n = 10);

    size_t get_num_threads() const { return thread_pool_.thread_count(); }

private:
    ThreadPool thread_pool_;
    HashAlgorithm default_algorithm_;
};

} // namespace swiftfs
