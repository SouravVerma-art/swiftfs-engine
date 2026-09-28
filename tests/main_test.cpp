#include "swiftfs.hpp"

#include <iostream>
#include <cassert>
#include <fstream>
#include <filesystem>

using namespace swiftfs;

void test_hasher() {
    std::cout << "[Test] Running Hasher tests..." << std::endl;
    
    std::string test_data = "Hello, SwiftFS! Fast filesystem analysis engine.";
    
    // Test XXH64
    auto res_xxh = Hasher::hash_string(test_data, HashAlgorithm::XXH64);
    assert(res_xxh.success);
    assert(!res_xxh.hex_digest.empty());
    assert(res_xxh.numeric_hash != 0);

    // Test SHA256
    auto res_sha = Hasher::hash_string(test_data, HashAlgorithm::SHA256);
    assert(res_sha.success);
    assert(res_sha.hex_digest.length() == 64);

    // Test CRC32
    auto res_crc = Hasher::hash_string(test_data, HashAlgorithm::CRC32);
    assert(res_crc.success);
    assert(!res_crc.hex_digest.empty());

    std::cout << "  ✓ Hasher unit tests passed successfully." << std::endl;
}

void test_scanner_and_analyzer() {
    std::cout << "[Test] Running Scanner and Analyzer tests..." << std::endl;

    // Create temporary test environment
    fs::path temp_dir = fs::temp_directory_path() / "swiftfs_test_dir";
    fs::remove_all(temp_dir);
    fs::create_directories(temp_dir / "subdir");

    std::ofstream(temp_dir / "file1.txt") << "Duplicate content sample A";
    std::ofstream(temp_dir / "file2.txt") << "Duplicate content sample A"; // duplicate of file1
    std::ofstream(temp_dir / "subdir" / "file3.txt") << "Unique content sample B";
    std::ofstream(temp_dir / "binary.dat") << "0123456789abcdef";

    // Scan
    ScanOptions opts;
    opts.recursive = true;
    Scanner scanner(opts);
    ScanResult result = scanner.scan(temp_dir.string());

    assert(result.stats.total_files == 4);
    assert(result.stats.total_directories >= 1);

    // Batch Process & Duplicates
    BatchProcessor processor(2, HashAlgorithm::XXH64);
    ProcessingReport report = processor.process_directory(temp_dir.string(), opts);

    assert(report.files_hashed == 4);
    assert(report.duplicate_groups.size() == 1);
    assert(report.duplicate_groups[0].file_paths.size() == 2);
    assert(report.total_wasted_bytes > 0);

    // Cleanup
    fs::remove_all(temp_dir);

    std::cout << "  ✓ Scanner & Duplicate Analyzer tests passed successfully." << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "        SwiftFS Test Suite              " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_hasher();
        test_scanner_and_analyzer();
        std::cout << "\n✅ All SwiftFS tests passed!\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
