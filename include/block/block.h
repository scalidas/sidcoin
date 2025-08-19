#ifndef BLOCK_BLOCK_H
#define BLOCK_BLOCK_H

#include <chrono>
#include <string>
#include <vector>

#include "sidcoin_constants.h"
#include "transaction/transaction.h"

namespace block {
	struct serialized_block {
		std::array<unsigned char, SHA256_HASH_SIZE> prev_hash;
		std::array<unsigned char, SERIALIZED_TIMESTAMP_SIZE> timestamp;
		std::array<unsigned char, NONCE_SIZE> nonce;

		transaction::serialized_transaction_with_signature tx1;
		transaction::serialized_transaction_with_signature tx2;
		transaction::serialized_transaction_with_signature tx3;
	};

	class Block {
		private:
			std::string sidcoin_version_;
			long long index_;
			std::chrono::system_clock::time_point timestamp_;
			std::vector<transaction::Transaction> transactions_;
			uint32_t nonce_;
			std::array<unsigned char, SHA256_HASH_SIZE> prev_hash_;

		public:
			Block(nlohmann::json block_json);

			bool isValid();
			bool checkNonce();

			void setNonce(int nonce);

			friend serialized_block* serialize_block(const block::Block& block);
			
	};

	serialized_block* serialize_block(const block::Block& block);
}

#endif