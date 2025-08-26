#include <vector>
#include <string>

#include <openssl/sha.h>
#include <openssl/crypto.h>

#include "crypto/sha256.h"
#include "transaction/transaction.h"
#include "block/block.h"


/*
Return hash of string. Return is set to 0 on sucess and -1 on failure
*/
std::vector<unsigned char> crypto::sha256(const std::string& input, int& ret) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash.data());

    if (hash_ret != hash.data()) {
        ret = -1;
    }

    return hash;
}

/*
Return hash of transaction without signature. Return is set to 0 on sucess and -1 on failure
*/
crypto::sha256_hash crypto::sha256_transaction_without_signature(transaction::serialized_transaction_without_signature* input, int& ret) {
    ret = 0;
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(input), sizeof(transaction::serialized_transaction_without_signature), hash.data());

    if (hash_ret != hash.data()) {
        ret = -1;
    }

    return hash;
}

/*
Return hash of transaction with signature. Return is set to 0 on sucess and -1 on failure
*/
crypto::sha256_hash crypto::sha256_transaction_with_signature(transaction::serialized_transaction_with_signature* input, int& ret) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(input), sizeof(transaction::serialized_transaction_with_signature), hash.data());

    if (hash_ret != hash.data()) {
        ret = -1;
    }

    return hash;
}

/*
Return hash of block. Return is set to 0 on sucess and -1 on failure
*/
crypto::sha256_hash crypto::sha256_block(block::serialized_block* input, int& ret) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash;
    unsigned char* hash_ret = SHA256(reinterpret_cast<const unsigned char*>(input), sizeof(block::serialized_block), hash.data());

    if (hash_ret != hash.data()) {
        ret = -1;
    }

    return hash;
}