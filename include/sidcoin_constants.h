#ifndef SIDCOIN_CONSTANTS_H
#define SIDCOIN_CONSTANTS_H

#include <cstdint>
#include <openssl/sha.h>

constexpr int NUM_TRANSACTIONS_PER_BLOCK = 3;
constexpr int NUM_LEADING_ZEROS_HASH = 0;

constexpr int MINING_REWARD = 10;

constexpr int EC_PUBLIC_KEY_SIZE_UNCOMPRESSED = 65;
constexpr int TX_AMOUNT_SIZE = 4;
constexpr int ECDSA_SIGNATURE_SIZE = 64;
constexpr int SHA256_HASH_SIZE = SHA256_DIGEST_LENGTH;
constexpr int SERIALIZED_TIMESTAMP_SIZE = 8;
constexpr int NONCE_SIZE = sizeof(uint32_t);

#endif