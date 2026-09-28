#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <string_view>
#include <optional>

namespace swiftfs
{

    /**
     * @brief Supported hashing algorithms for content verification and duplicate detection.
     */
    enum class HashAlgorithm
    {
        XXH64,    // High-speed 64-bit non-cryptographic hash (fastest)
        CRC32,    // Standard 32-bit Cyclic Redundancy Check
        FNV1A_64, // Fast 64-bit Fowler–Noll–Vo hash
        SHA256,   // Cryptographic SHA-256
        MD5       // Legacy MD5 checksum
    };

    /**
     * @brief Result of a file or buffer hashing operation.
     */
    struct HashResult
    {
        std::string hex_digest;
        uint64_t numeric_hash{0}; // 64-bit integer hash for fast in-memory hash-map keys
        uint64_t bytes_hashed{0};
        double duration_seconds{0.0};
        bool success{false};
        std::string error_message;
    };

    /**
     * @brief Options for hashing operations.
     */
    struct HashOptions
    {
        HashAlgorithm algorithm{HashAlgorithm::XXH64};
        size_t buffer_size{64 * 1024}; // 64 KB streaming buffer
        bool quick_mode{false};        // If true, hashes only the first N bytes (prefix check)
        size_t quick_mode_bytes{4096}; // Prefix size in bytes for quick mode
    };

    /**
     * @brief High-performance streaming and file hasher.
     */
    class Hasher
    {
    public:
        explicit Hasher(HashOptions options = {});

        /**
         * @brief Computes hash of an entire file on disk using buffered streaming.
         */
        HashResult hash_file(const std::string &filepath) const;

        /**
         * @brief Computes hash of an entire file using a specified algorithm.
         */
        static HashResult hash_file(const std::string &filepath, HashAlgorithm algorithm, size_t buffer_size = 64 * 1024);

        /**
         * @brief Computes a fast prefix hash (e.g. first 4KB) for rapid duplicate candidate filtering.
         */
        static HashResult quick_hash_file(const std::string &filepath, size_t prefix_bytes = 4096, HashAlgorithm algorithm = HashAlgorithm::XXH64);

        /**
         * @brief Computes hash of an in-memory byte buffer.
         */
        static HashResult hash_bytes(const uint8_t *data, size_t length, HashAlgorithm algorithm = HashAlgorithm::XXH64);

        /**
         * @brief Computes hash of a string.
         */
        static HashResult hash_string(std::string_view data, HashAlgorithm algorithm = HashAlgorithm::XXH64);

        /**
         * @brief Converts algorithm enum to string name.
         */
        static std::string algorithm_to_string(HashAlgorithm algo);

        /**
         * @brief Parses algorithm name string to enum.
         */
        static std::optional<HashAlgorithm> string_to_algorithm(std::string_view name);

        void set_options(const HashOptions &options) { options_ = options; }
        const HashOptions &get_options() const { return options_; }

    private:
        HashOptions options_;
    };

} // namespace swiftfs
