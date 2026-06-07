#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <vector>
#include <string>
#include <optional>
#include <array>

#include <openssl/sha.h>
#include "constants.h"

namespace transaction {
    struct serialized_transaction_without_signature;
    struct serialized_transaction_with_signature;
}

namespace block {
    struct serialized_block;
}

namespace crypto {
    class SHA256Hash {
    public:
        SHA256Hash() = default;

        static std::optional<SHA256Hash> hash(const std::string& input);
        static std::optional<SHA256Hash> hash(const transaction::serialized_transaction_without_signature& input);
        static std::optional<SHA256Hash> hash(const transaction::serialized_transaction_with_signature& input);
        static std::optional<SHA256Hash> hash(const block::serialized_block& input);

        std::string toHexString() const;
        static std::optional<SHA256Hash> fromHexString(const std::string& hex);

        const unsigned char* data() const { return hash_.data(); }
        size_t size() const { return hash_.size(); }

        bool operator==(const SHA256Hash& other) const {
            return hash_ == other.hash_;
        }
        bool operator!=(const SHA256Hash& other) const {
            return hash_ != other.hash_;
        }
        bool operator<(const SHA256Hash& other) const {
            return hash_ < other.hash_;
        }

    private:
        explicit SHA256Hash(const std::array<unsigned char, SHA256_HASH_SIZE>& hash) : hash_(hash) {}

        std::array<unsigned char, SHA256_HASH_SIZE> hash_{};
    };
}

namespace std {
    template <>
    struct hash<crypto::SHA256Hash> {
        size_t operator()(const crypto::SHA256Hash& h) const {
            size_t res = 0;
            for (size_t i = 0; i < sizeof(size_t) && i < h.size(); ++i) {
                res ^= static_cast<size_t>(h.data()[i]) << (i * 8);
            }
            return res;
        }
    };
}

#endif