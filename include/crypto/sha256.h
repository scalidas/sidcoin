#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <vector>
#include <string>

#include <openssl/sha.h>

namespace transaction
{
	struct serialized_transaction_without_signature;
	struct serialized_transaction_with_signature;
}

namespace block
{
	struct serialized_block;
}

namespace crypto
{
	std::vector<unsigned char> sha256(const std::string& input, int& ret);

	std::array<unsigned char, SHA256_DIGEST_LENGTH> sha256_transaction_without_signature(transaction::serialized_transaction_without_signature* input, int& ret);
	std::array<unsigned char, SHA256_DIGEST_LENGTH> sha256_transaction_with_signature(transaction::serialized_transaction_with_signature* input, int& ret);

	std::array<unsigned char, SHA256_DIGEST_LENGTH> sha256_block(block::serialized_block* input, int& ret);
}

#endif