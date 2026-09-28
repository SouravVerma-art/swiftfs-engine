#include "processor.hpp"
#include "analyzer.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>

namespace swiftfs {

// ---------------------------------------------------------------------------
// ThreadPool Implementation
// ---------------------------------------------------------------------------
ThreadPool::ThreadPool(size_t thread_count) {
    if (thread_count == 0) {
        thread_count = std::max(1u, std::thread::hardware_concurrency());
    }

    workers_.reserve(thread_count);
    for (size_t i = 0; i < thread_count; ++i) {
        workers_.emplace_back([this]() {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex_);
                    this->condition_.wait(lock, [this]() {
                        return this->stop_ || !this->tasks_.empty();
                    });

                    if (this->stop_ && this->tasks_.empty()) {
                        return;
                    }

                    task = std::move(this->tasks_.front());
                    this->tasks_.pop();
                    this->active_tasks_++;
                }

                try {
                    task();
                } catch (...) {
                    // Prevent unhandled worker thread exceptions from terminating the process
                }

                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex_);
                    this->active_tasks_--;
                    if (this->tasks_.empty() && this->active_tasks_ == 0) {
                        this->idle_condition_.notify_all();
                    }
                }
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    condition_.notify_all();
    for (std::thread& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void ThreadPool::wait_idle() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    idle_condition_.wait(lock, [this]() {
        return tasks_.empty() && active_tasks_ == 0;
    });
}

// ---------------------------------------------------------------------------
// BatchProcessor Implementation
// ---------------------------------------------------------------------------
BatchProcessor::BatchProcessor(size_t num_threads, HashAlgorithm algorithm)
    : thread_pool_(num_threads), default_algorithm_(algorithm) {}

std::vector<ProcessedFile> BatchProcessor::hash_files_parallel(
    const std::vector<FileEntry>& files,
    const HashOptions& hash_opts,
    ProgressCallback progress_cb) {

    std::vector<ProcessedFile> results(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        results[i].entry = files[i];
    }

    if (files.empty()) {
        return results;
    }

    std::atomic<size_t> completed{0};
    std::atomic<uint64_t> bytes_done{0};
    std::mutex cb_mutex;
    size_t total = files.size();

    std::vector<std::future<void>> futures;
    futures.reserve(files.size());

    Hasher hasher(hash_opts);

    for (size_t i = 0; i < files.size(); ++i) {
        futures.push_back(thread_pool_.enqueue([&, i]() {
            if (results[i].entry.is_regular_file) {
                results[i].hash = hasher.hash_file(results[i].entry.path);
                bytes_done += results[i].hash.bytes_hashed;
            }

            size_t c = ++completed;
            if (progress_cb) {
                std::lock_guard<std::mutex> lock(cb_mutex);
                ProgressUpdate update;
                update.completed_items = c;
                update.total_items = total;
                update.bytes_processed = bytes_done.load();
                update.current_file = results[i].entry.filename;
                progress_cb(update);
            }
        }));
    }

    for (auto& fut : futures) {
        fut.get();
    }

    return results;
}

std::vector<DuplicateGroup> BatchProcessor::analyze_duplicates(const std::vector<ProcessedFile>& processed_files) {
    return Analyzer::find_duplicates(processed_files);
}

std::vector<ExtensionStats> BatchProcessor::analyze_extensions(const std::vector<FileEntry>& entries) {
    return Analyzer::summarize_extensions(entries);
}

std::vector<ProcessedFile> BatchProcessor::get_largest_files(const std::vector<ProcessedFile>& processed_files, size_t top_n) {
    return Analyzer::find_largest_files(processed_files, top_n);
}

ProcessingReport BatchProcessor::process_directory(
    const std::string& root_path,
    const ScanOptions& scan_opts,
    const HashOptions& hash_opts,
    ProgressCallback progress_cb) {

    auto start_time = std::chrono::steady_clock::now();

    Scanner scanner(scan_opts);
    ScanResult scan_res = scanner.scan(root_path);

    // Filter only regular files for content hashing
    std::vector<FileEntry> regular_files;
    regular_files.reserve(scan_res.entries.size());
    for (const auto& entry : scan_res.entries) {
        if (entry.is_regular_file) {
            regular_files.push_back(entry);
        }
    }

    std::vector<ProcessedFile> processed_files = hash_files_parallel(regular_files, hash_opts, progress_cb);

    auto end_time = std::chrono::steady_clock::now();
    double total_duration = std::chrono::duration<double>(end_time - start_time).count();

    return Analyzer::generate_report(scan_res.stats, processed_files, total_duration, scan_res.errors);
}

} // namespace swiftfs
