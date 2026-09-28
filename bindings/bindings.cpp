#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

#include "swiftfs.hpp"

namespace py = pybind11;
using namespace swiftfs;

PYBIND11_MODULE(_swiftfs_core, m) {
    m.doc() = "SwiftFS - High-Performance Filesystem Scanner and Analysis Engine";

    // -----------------------------------------------------------------------
    // Scanner Module Bindings
    // -----------------------------------------------------------------------
    py::class_<FileEntry>(m, "FileEntry")
        .def(py::init<>())
        .def_readwrite("path", &FileEntry::path)
        .def_readwrite("filename", &FileEntry::filename)
        .def_readwrite("extension", &FileEntry::extension)
        .def_readwrite("size_bytes", &FileEntry::size_bytes)
        .def_readwrite("last_modified_epoch", &FileEntry::last_modified_epoch)
        .def_readwrite("is_directory", &FileEntry::is_directory)
        .def_readwrite("is_regular_file", &FileEntry::is_regular_file)
        .def_readwrite("is_symlink", &FileEntry::is_symlink)
        .def_readwrite("is_hidden", &FileEntry::is_hidden)
        .def("__repr__", [](const FileEntry& fe) {
            return "<FileEntry path='" + fe.path + "' size=" + std::to_string(fe.size_bytes) + ">";
        });

    py::class_<ScanOptions>(m, "ScanOptions")
        .def(py::init<>())
        .def_readwrite("recursive", &ScanOptions::recursive)
        .def_readwrite("max_depth", &ScanOptions::max_depth)
        .def_readwrite("follow_symlinks", &ScanOptions::follow_symlinks)
        .def_readwrite("include_hidden", &ScanOptions::include_hidden)
        .def_readwrite("min_file_size", &ScanOptions::min_file_size)
        .def_readwrite("max_file_size", &ScanOptions::max_file_size)
        .def_readwrite("include_extensions", &ScanOptions::include_extensions)
        .def_readwrite("exclude_extensions", &ScanOptions::exclude_extensions)
        .def_readwrite("exclude_patterns", &ScanOptions::exclude_patterns);

    py::class_<ScanStats>(m, "ScanStats")
        .def(py::init<>())
        .def_readwrite("total_files", &ScanStats::total_files)
        .def_readwrite("total_directories", &ScanStats::total_directories)
        .def_readwrite("total_bytes", &ScanStats::total_bytes)
        .def_readwrite("total_errors", &ScanStats::total_errors)
        .def_readwrite("elapsed_time_seconds", &ScanStats::elapsed_time_seconds);

    py::class_<ScanResult>(m, "ScanResult")
        .def(py::init<>())
        .def_readwrite("entries", &ScanResult::entries)
        .def_readwrite("stats", &ScanResult::stats)
        .def_readwrite("errors", &ScanResult::errors);

    py::class_<Scanner>(m, "Scanner")
        .def(py::init<ScanOptions>(), py::arg("options") = ScanOptions{})
        .def("scan", &Scanner::scan, py::arg("root_path"), py::call_guard<py::gil_scoped_release>(),
             "Recursively scan a directory and return a ScanResult")
        .def("scan_streaming", &Scanner::scan_streaming,
             py::arg("root_path"), py::arg("on_entry"), py::arg("on_error") = nullptr,
             "Stream scanned entries directly into a Python callback")
        .def("set_options", &Scanner::set_options)
        .def("get_options", &Scanner::get_options);

    // -----------------------------------------------------------------------
    // Hasher Module Bindings
    // -----------------------------------------------------------------------
    py::enum_<HashAlgorithm>(m, "HashAlgorithm")
        .value("XXH64", HashAlgorithm::XXH64)
        .value("CRC32", HashAlgorithm::CRC32)
        .value("FNV1A_64", HashAlgorithm::FNV1A_64)
        .value("SHA256", HashAlgorithm::SHA256)
        .value("MD5", HashAlgorithm::MD5)
        .export_values();

    py::class_<HashResult>(m, "HashResult")
        .def(py::init<>())
        .def_readwrite("hex_digest", &HashResult::hex_digest)
        .def_readwrite("numeric_hash", &HashResult::numeric_hash)
        .def_readwrite("bytes_hashed", &HashResult::bytes_hashed)
        .def_readwrite("duration_seconds", &HashResult::duration_seconds)
        .def_readwrite("success", &HashResult::success)
        .def_readwrite("error_message", &HashResult::error_message)
        .def("__repr__", [](const HashResult& hr) {
            return "<HashResult digest='" + hr.hex_digest + "' bytes=" + std::to_string(hr.bytes_hashed) + ">";
        });

    py::class_<HashOptions>(m, "HashOptions")
        .def(py::init<>())
        .def_readwrite("algorithm", &HashOptions::algorithm)
        .def_readwrite("buffer_size", &HashOptions::buffer_size)
        .def_readwrite("quick_mode", &HashOptions::quick_mode)
        .def_readwrite("quick_mode_bytes", &HashOptions::quick_mode_bytes);

    py::class_<Hasher>(m, "Hasher")
        .def(py::init<HashOptions>(), py::arg("options") = HashOptions{})
        .def("hash_file", py::overload_cast<const std::string&>(&Hasher::hash_file, py::const_),
             py::arg("filepath"), py::call_guard<py::gil_scoped_release>())
        .def_static("hash_file_static", py::overload_cast<const std::string&, HashAlgorithm, size_t>(&Hasher::hash_file),
             py::arg("filepath"), py::arg("algorithm") = HashAlgorithm::XXH64, py::arg("buffer_size") = 64 * 1024,
             py::call_guard<py::gil_scoped_release>())
        .def_static("quick_hash_file", &Hasher::quick_hash_file,
             py::arg("filepath"), py::arg("prefix_bytes") = 4096, py::arg("algorithm") = HashAlgorithm::XXH64,
             py::call_guard<py::gil_scoped_release>())
        .def_static("hash_string", &Hasher::hash_string,
             py::arg("data"), py::arg("algorithm") = HashAlgorithm::XXH64)
        .def_static("algorithm_to_string", &Hasher::algorithm_to_string)
        .def_static("string_to_algorithm", &Hasher::string_to_algorithm);

    // -----------------------------------------------------------------------
    // Processor & Analyzer Module Bindings
    // -----------------------------------------------------------------------
    py::class_<ProcessedFile>(m, "ProcessedFile")
        .def(py::init<>())
        .def_readwrite("entry", &ProcessedFile::entry)
        .def_readwrite("hash", &ProcessedFile::hash)
        .def_readwrite("is_duplicate", &ProcessedFile::is_duplicate);

    py::class_<DuplicateGroup>(m, "DuplicateGroup")
        .def(py::init<>())
        .def_readwrite("hash", &DuplicateGroup::hash)
        .def_readwrite("file_size", &DuplicateGroup::file_size)
        .def_readwrite("file_paths", &DuplicateGroup::file_paths)
        .def_readwrite("wasted_bytes", &DuplicateGroup::wasted_bytes);

    py::class_<ExtensionStats>(m, "ExtensionStats")
        .def(py::init<>())
        .def_readwrite("extension", &ExtensionStats::extension)
        .def_readwrite("file_count", &ExtensionStats::file_count)
        .def_readwrite("total_bytes", &ExtensionStats::total_bytes)
        .def_readwrite("percentage_of_total_bytes", &ExtensionStats::percentage_of_total_bytes);

    py::class_<ProgressUpdate>(m, "ProgressUpdate")
        .def(py::init<>())
        .def_readwrite("completed_items", &ProgressUpdate::completed_items)
        .def_readwrite("total_items", &ProgressUpdate::total_items)
        .def_readwrite("bytes_processed", &ProgressUpdate::bytes_processed)
        .def_readwrite("current_file", &ProgressUpdate::current_file);

    py::class_<ProcessingReport>(m, "ProcessingReport")
        .def(py::init<>())
        .def_readwrite("scan_stats", &ProcessingReport::scan_stats)
        .def_readwrite("files_hashed", &ProcessingReport::files_hashed)
        .def_readwrite("total_hashed_bytes", &ProcessingReport::total_hashed_bytes)
        .def_readwrite("processing_duration_seconds", &ProcessingReport::processing_duration_seconds)
        .def_readwrite("duplicate_groups", &ProcessingReport::duplicate_groups)
        .def_readwrite("total_duplicate_files", &ProcessingReport::total_duplicate_files)
        .def_readwrite("total_wasted_bytes", &ProcessingReport::total_wasted_bytes)
        .def_readwrite("extension_summary", &ProcessingReport::extension_summary)
        .def_readwrite("largest_files", &ProcessingReport::largest_files)
        .def_readwrite("errors", &ProcessingReport::errors);

    py::class_<BatchProcessor>(m, "BatchProcessor")
        .def(py::init<size_t, HashAlgorithm>(), py::arg("num_threads") = 0, py::arg("algorithm") = HashAlgorithm::XXH64)
        .def("process_directory", &BatchProcessor::process_directory,
             py::arg("root_path"), py::arg("scan_opts") = ScanOptions{}, py::arg("hash_opts") = HashOptions{},
             py::arg("progress_cb") = nullptr, py::call_guard<py::gil_scoped_release>())
        .def("hash_files_parallel", &BatchProcessor::hash_files_parallel,
             py::arg("files"), py::arg("hash_opts") = HashOptions{}, py::arg("progress_cb") = nullptr,
             py::call_guard<py::gil_scoped_release>())
        .def_property_readonly("num_threads", &BatchProcessor::get_num_threads);

    py::class_<Analyzer>(m, "Analyzer")
        .def_static("find_duplicates", &Analyzer::find_duplicates)
        .def_static("summarize_extensions", &Analyzer::summarize_extensions)
        .def_static("find_largest_files", &Analyzer::find_largest_files, py::arg("files"), py::arg("top_n") = 10)
        .def_static("generate_report", &Analyzer::generate_report,
             py::arg("scan_stats"), py::arg("processed_files"), py::arg("total_duration_seconds"),
             py::arg("errors") = std::vector<std::string>{});
}
