#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <optional>

#include <openssl/sha.h>
#include <openssl/crypto.h>

#include "crypto/sha256.h"
#include "transaction/transaction.h"
#include "block/block.h"

std::optional<crypto::SHA256Hash> crypto::SHA256Hash::hash(const std::string& input) {
    std::array<unsigned char, SHA256_HASH_SIZE> hash_arr;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash_arr.data());

    if (hash_ret != hash_arr.data()) {
        return std::nullopt;
    }

    return SHA256Hash(hash_arr);
}

std::optional<crypto::SHA256Hash> crypto::SHA256Hash::hash(const transaction::serialized_transaction_without_signature& input) {
    std::array<unsigned char, SHA256_HASH_SIZE> hash_arr;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(&input), sizeof(transaction::serialized_transaction_without_signature), hash_arr.data());

    if (hash_ret != hash_arr.data()) {
        return std::nullopt;
    }

    return SHA256Hash(hash_arr);
}

std::optional<crypto::SHA256Hash> crypto::SHA256Hash::hash(const transaction::serialized_transaction_with_signature& input) {
    std::array<unsigned char, SHA256_HASH_SIZE> hash_arr;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(&input), sizeof(transaction::serialized_transaction_with_signature), hash_arr.data());

    if (hash_ret != hash_arr.data()) {
        return std::nullopt;
    }

    return SHA256Hash(hash_arr);
}

std::optional<crypto::SHA256Hash> crypto::SHA256Hash::hash(const block::serialized_block& input) {
    std::array<unsigned char, SHA256_HASH_SIZE> hash_arr;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(&input), sizeof(block::serialized_block), hash_arr.data());

    if (hash_ret != hash_arr.data()) {
        return std::nullopt;
    }

    return SHA256Hash(hash_arr);
}

std::string crypto::SHA256Hash::toHexString() const {
    std::stringstream ss;
    for (auto byte : hash_) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
    }

    return ss.str();
}

std::optional<crypto::SHA256Hash> crypto::SHA256Hash::fromHexString(const std::string& hex) {
    if (hex.length() != SHA256_HASH_SIZE * 2) {
        return std::nullopt;
    }

    std::array<unsigned char, SHA256_HASH_SIZE> hash_arr;

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), NULL, 16));
        hash_arr[i / 2] = byte;
    }

    return SHA256Hash(hash_arr);
}