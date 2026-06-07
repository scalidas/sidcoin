#ifndef SIDCOIN_CONSTANTS_H
#define SIDCOIN_CONSTANTS_H

#include <cstdint>
#include <string>

#include <openssl/sha.h>

//General
const std::string SIDCOIN_VERSION = "v0.1";

//Specifications for blocks, mining
constexpr int NUM_TRANSACTIONS_PER_BLOCK = 3;
constexpr int NUM_LEADING_ZEROS_HASH = 0;
constexpr int MINING_REWARD = 10;

//Cryptography Related
constexpr int EC_PUBLIC_KEY_SIZE_UNCOMPRESSED = 65;
constexpr int TX_AMOUNT_SIZE = sizeof(double);
constexpr int ECDSA_SIGNATURE_SIZE = 64;
constexpr int SHA256_HASH_SIZE = SHA256_DIGEST_LENGTH;
constexpr int SERIALIZED_TIMESTAMP_SIZE = 8;
constexpr int NONCE_SIZE = sizeof(uint32_t);

constexpr int GENESIS_BLOCK_AMOUNT = 150;

const std::string ALL_BLOCKS_FILE = "sidcoin_files/all_blocks.json";

#endif