#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <vector>
#include <string>

#include <openssl/sha.h>
#include "sidcoin_constants.h"

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
	using sha256_hash = std::array<unsigned char, SHA256_HASH_SIZE>;

	std::vector<unsigned char> sha256(const std::string& input, int& ret);

	crypto::sha256_hash sha256_transaction_without_signature(transaction::serialized_transaction_without_signature* input, int& ret);
	crypto::sha256_hash sha256_transaction_with_signature(transaction::serialized_transaction_with_signature* input, int& ret);

	crypto::sha256_hash sha256_block(block::serialized_block* input, int& ret);

	
}

#endif