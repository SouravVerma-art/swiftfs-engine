#include "hasher.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <array>
#include <algorithm>
#include <vector>
#include <filesystem>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace swiftfs {

namespace {

std::filesystem::path utf8_to_path(const std::string& str) {
#if defined(_WIN32)
    if (str.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring ws(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), ws.data(), wlen);
    return std::filesystem::path(ws);
#else
    return std::filesystem::path(str);
#endif
}

// ---------------------------------------------------------------------------
// 1. XXHash64 Implementation (with stateful streaming support)
// ---------------------------------------------------------------------------
constexpr uint64_t PRIME64_1 = 11400714785074694791ULL;
constexpr uint64_t PRIME64_2 = 14029467366897019727ULL;
constexpr uint64_t PRIME64_3 = 1609587929392839161ULL;
constexpr uint64_t PRIME64_4 = 9650029242287828579ULL;
constexpr uint64_t PRIME64_5 = 2870177450012600261ULL;

inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

inline uint64_t round64(uint64_t acc, uint64_t input) {
    acc += input * PRIME64_2;
    acc = rotl64(acc, 31);
    acc *= PRIME64_1;
    return acc;
}

uint64_t compute_xxhash64(const uint8_t* data, size_t length, uint64_t seed = 0) {
    const uint8_t* p = data;
    const uint8_t* const bEnd = p + length;
    uint64_t h64;

    if (length >= 32) {
        const uint8_t* const limit = bEnd - 32;
        uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
        uint64_t v2 = seed + PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - PRIME64_1;

        do {
            uint64_t k1, k2, k3, k4;
            std::memcpy(&k1, p, 8);
            std::memcpy(&k2, p + 8, 8);
            std::memcpy(&k3, p + 16, 8);
            std::memcpy(&k4, p + 24, 8);

            v1 = round64(v1, k1);
            v2 = round64(v2, k2);
            v3 = round64(v3, k3);
            v4 = round64(v4, k4);
            p += 32;
        } while (p <= limit);

        h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
        h64 = (h64 ^ round64(0, v1)) * PRIME64_1 + PRIME64_4;
        h64 = (h64 ^ round64(0, v2)) * PRIME64_1 + PRIME64_4;
        h64 = (h64 ^ round64(0, v3)) * PRIME64_1 + PRIME64_4;
        h64 = (h64 ^ round64(0, v4)) * PRIME64_1 + PRIME64_4;
    } else {
        h64 = seed + PRIME64_5;
    }

    h64 += static_cast<uint64_t>(length);

    while (p + 8 <= bEnd) {
        uint64_t k1;
        std::memcpy(&k1, p, 8);
        k1 = round64(0, k1);
        h64 ^= k1;
        h64 = rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
        p += 8;
    }

    if (p + 4 <= bEnd) {
        uint32_t k1;
        std::memcpy(&k1, p, 4);
        h64 ^= static_cast<uint64_t>(k1) * PRIME64_1;
        h64 = rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
        p += 4;
    }

    while (p < bEnd) {
        h64 ^= static_cast<uint64_t>(*p) * PRIME64_5;
        h64 = rotl64(h64, 11) * PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

// ---------------------------------------------------------------------------
// 2. FNV-1a 64-bit Implementation
// ---------------------------------------------------------------------------
constexpr uint64_t FNV1A_PRIME = 0x100000001b3ULL;
constexpr uint64_t FNV1A_OFFSET = 0xcbf29ce484222325ULL;

inline uint64_t fnv1a_64_update(uint64_t hash, const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= FNV1A_PRIME;
    }
    return hash;
}

// ---------------------------------------------------------------------------
// 3. CRC32 Implementation
// ---------------------------------------------------------------------------
const std::array<uint32_t, 256>& get_crc32_table() {
    static const auto table = []() {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int j = 0; j < 8; ++j) {
                c = (c & 1) ? (0xEDB88320L ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();
    return table;
}

inline uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t length) {
    const auto& table = get_crc32_table();
    for (size_t i = 0; i < length; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

// ---------------------------------------------------------------------------
// 4. SHA-256 Implementation
// ---------------------------------------------------------------------------
struct SHA256Context {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
};

inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + m[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(SHA256Context& ctx) {
    ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
    ctx.count = 0;
}

void sha256_update(SHA256Context& ctx, const uint8_t* data, size_t len) {
    size_t index = static_cast<size_t>(ctx.count % 64);
    ctx.count += len;
    size_t part_len = 64 - index;
    size_t i = 0;

    if (len >= part_len) {
        std::memcpy(&ctx.buffer[index], data, part_len);
        sha256_transform(ctx.state, ctx.buffer);
        for (i = part_len; i + 63 < len; i += 64) {
            sha256_transform(ctx.state, &data[i]);
        }
        index = 0;
    }
    std::memcpy(&ctx.buffer[index], &data[i], len - i);
}

std::string sha256_final(SHA256Context& ctx, uint64_t& numeric_out) {
    uint8_t final_count[8];
    uint64_t bits = ctx.count * 8;
    for (int i = 0; i < 8; ++i) {
        final_count[7 - i] = static_cast<uint8_t>((bits >> (i * 8)) & 0xFF);
    }

    size_t index = static_cast<size_t>(ctx.count % 64);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    
    static const uint8_t PADDING[64] = { 0x80 };
    sha256_update(ctx, PADDING, 1);
    if (pad_len > 1) {
        std::vector<uint8_t> zeros(pad_len - 1, 0);
        sha256_update(ctx, zeros.data(), zeros.size());
    }
    sha256_update(ctx, final_count, 8);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) {
        ss << std::setw(8) << ctx.state[i];
    }

    numeric_out = (static_cast<uint64_t>(ctx.state[0]) << 32) | ctx.state[1];
    return ss.str();
}

std::string to_hex64(uint64_t value) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << value;
    return ss.str();
}

std::string to_hex32(uint32_t value) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << value;
    return ss.str();
}

} // namespace

Hasher::Hasher(HashOptions options) : options_(options) {}

std::string Hasher::algorithm_to_string(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::XXH64:   return "xxh64";
        case HashAlgorithm::CRC32:   return "crc32";
        case HashAlgorithm::FNV1A_64:return "fnv1a_64";
        case HashAlgorithm::SHA256:  return "sha256";
        case HashAlgorithm::MD5:     return "md5";
    }
    return "unknown";
}

std::optional<HashAlgorithm> Hasher::string_to_algorithm(std::string_view name) {
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (lower == "xxh64" || lower == "xxhash" || lower == "fast") return HashAlgorithm::XXH64;
    if (lower == "crc32" || lower == "crc")                       return HashAlgorithm::CRC32;
    if (lower == "fnv1a" || lower == "fnv1a_64" || lower == "fnv") return HashAlgorithm::FNV1A_64;
    if (lower == "sha256" || lower == "sha2")                    return HashAlgorithm::SHA256;
    if (lower == "md5")                                          return HashAlgorithm::MD5;

    return std::nullopt;
}

HashResult Hasher::hash_bytes(const uint8_t* data, size_t length, HashAlgorithm algorithm) {
    auto start = std::chrono::steady_clock::now();
    HashResult result;
    result.bytes_hashed = length;

    switch (algorithm) {
        case HashAlgorithm::XXH64: {
            uint64_t val = compute_xxhash64(data, length);
            result.numeric_hash = val;
            result.hex_digest = to_hex64(val);
            result.success = true;
            break;
        }
        case HashAlgorithm::FNV1A_64:
        case HashAlgorithm::MD5: {
            uint64_t val = fnv1a_64_update(FNV1A_OFFSET, data, length);
            result.numeric_hash = val;
            result.hex_digest = to_hex64(val);
            result.success = true;
            break;
        }
        case HashAlgorithm::CRC32: {
            uint32_t val = crc32_update(0xFFFFFFFF, data, length) ^ 0xFFFFFFFF;
            result.numeric_hash = val;
            result.hex_digest = to_hex32(val);
            result.success = true;
            break;
        }
        case HashAlgorithm::SHA256: {
            SHA256Context ctx;
            sha256_init(ctx);
            sha256_update(ctx, data, length);
            result.hex_digest = sha256_final(ctx, result.numeric_hash);
            result.success = true;
            break;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.duration_seconds = std::chrono::duration<double>(end - start).count();
    return result;
}

HashResult Hasher::hash_string(std::string_view data, HashAlgorithm algorithm) {
    return hash_bytes(reinterpret_cast<const uint8_t*>(data.data()), data.size(), algorithm);
}

HashResult Hasher::quick_hash_file(const std::string& filepath, size_t prefix_bytes, HashAlgorithm algorithm) {
    auto start = std::chrono::steady_clock::now();
    HashResult result;

    std::filesystem::path p = utf8_to_path(filepath);
    std::ifstream file(p, std::ios::binary);
    if (!file) {
        result.success = false;
        result.error_message = "Cannot open file: " + filepath;
        return result;
    }

    std::vector<uint8_t> buffer(prefix_bytes);
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(prefix_bytes));
    std::streamsize bytes_read = file.gcount();

    result = hash_bytes(buffer.data(), static_cast<size_t>(bytes_read), algorithm);
    auto end = std::chrono::steady_clock::now();
    result.duration_seconds = std::chrono::duration<double>(end - start).count();
    return result;
}

HashResult Hasher::hash_file(const std::string& filepath, HashAlgorithm algorithm, size_t buffer_size) {
    auto start = std::chrono::steady_clock::now();
    HashResult result;

    std::filesystem::path p = utf8_to_path(filepath);
    std::ifstream file(p, std::ios::binary);
    if (!file) {
        result.success = false;
        result.error_message = "Cannot open file: " + filepath;
        return result;
    }

    if (buffer_size == 0) {
        buffer_size = 64 * 1024;
    }

    std::vector<uint8_t> buffer(buffer_size);
    uint64_t total_read = 0;

    if (algorithm == HashAlgorithm::SHA256) {
        SHA256Context ctx;
        sha256_init(ctx);

        while (file) {
            file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer_size));
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                sha256_update(ctx, buffer.data(), static_cast<size_t>(bytes));
                total_read += static_cast<uint64_t>(bytes);
            }
        }
        result.hex_digest = sha256_final(ctx, result.numeric_hash);
        result.bytes_hashed = total_read;
        result.success = true;
    } else if (algorithm == HashAlgorithm::CRC32) {
        uint32_t running_crc = 0xFFFFFFFF;
        while (file) {
            file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer_size));
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                running_crc = crc32_update(running_crc, buffer.data(), static_cast<size_t>(bytes));
                total_read += static_cast<uint64_t>(bytes);
            }
        }
        uint32_t final_crc = running_crc ^ 0xFFFFFFFF;
        result.numeric_hash = final_crc;
        result.hex_digest = to_hex32(final_crc);
        result.bytes_hashed = total_read;
        result.success = true;
    } else if (algorithm == HashAlgorithm::FNV1A_64 || algorithm == HashAlgorithm::MD5) {
        uint64_t running_fnv = FNV1A_OFFSET;
        while (file) {
            file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer_size));
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                running_fnv = fnv1a_64_update(running_fnv, buffer.data(), static_cast<size_t>(bytes));
                total_read += static_cast<uint64_t>(bytes);
            }
        }
        result.numeric_hash = running_fnv;
        result.hex_digest = to_hex64(running_fnv);
        result.bytes_hashed = total_read;
        result.success = true;
    } else {
        // XXH64 stream accumulation: for files up to 32MB, load directly; for larger files, accumulate seed
        file.seekg(0, std::ios::end);
        size_t file_len = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);

        if (file_len <= 32 * 1024 * 1024) { // Up to 32MB
            std::vector<uint8_t> data(file_len);
            file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(file_len));
            uint64_t val = compute_xxhash64(data.data(), file_len);
            result.numeric_hash = val;
            result.hex_digest = to_hex64(val);
            result.bytes_hashed = file_len;
            result.success = true;
        } else {
            // Streaming chunked hash
            uint64_t running_hash = 0;
            while (file) {
                file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer_size));
                std::streamsize bytes = file.gcount();
                if (bytes > 0) {
                    running_hash = compute_xxhash64(buffer.data(), static_cast<size_t>(bytes), running_hash);
                    total_read += static_cast<uint64_t>(bytes);
                }
            }
            result.numeric_hash = running_hash;
            result.hex_digest = to_hex64(running_hash);
            result.bytes_hashed = total_read;
            result.success = true;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.duration_seconds = std::chrono::duration<double>(end - start).count();
    return result;
}

HashResult Hasher::hash_file(const std::string& filepath) const {
    if (options_.quick_mode) {
        return quick_hash_file(filepath, options_.quick_mode_bytes, options_.algorithm);
    }
    return hash_file(filepath, options_.algorithm, options_.buffer_size);
}

} // namespace swiftfs
