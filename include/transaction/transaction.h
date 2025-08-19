#ifndef TRANSACTION_TRANSACTION_H
#define TRANSACTION_TRANSACTION_H

#include <string>
#include <chrono>

#include <openssl/ec.h>
#include <vector>

#include "nlohmann/json.hpp"

#include "sidcoin.h"
#include "sidcoin_constants.h"
#include "transaction_input.h"
#include "transaction_output.h"
#include "crypto/ecdsa.h"

namespace block {
	class Block;
}

namespace transaction {

	struct serialized_transaction_with_signature {
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> sender_public_key;
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> receiver_public_key;
		std::array<uint8_t, TX_AMOUNT_SIZE> amount;
		std::array<uint8_t, ECDSA_SIGNATURE_SIZE> signature;
	};

	struct serialized_transaction_without_signature {
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> sender_public_key;
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> receiver_public_key;
		std::array<uint8_t, TX_AMOUNT_SIZE> amount;
	};

	class Transaction {

		private:
			std::string sidcoin_version_;
			uint64_t block_index_;
			std::chrono::system_clock::time_point timestamp_;
			EC_KEY* sender_public_key_;
			EC_KEY* receiver_public_key_;
			double amount_;
			std::vector<transaction::TransactionInput> inputs_;
			TransactionOutput output1_;
			TransactionOutput output2_;

			ECDSA_SIG* sender_signature_;
		
		public:
			Transaction(nlohmann::json transaction_json);
			
			~Transaction();
			Transaction(const Transaction& other);
			Transaction& operator=(const Transaction& other);

			bool isValid();

			friend serialized_transaction_with_signature* serialize_transaction_with_signature(Transaction transaction);
			friend serialized_transaction_without_signature* serialize_transaction_without_signature(Transaction transaction);

			friend class block::Block;


		
	};

	serialized_transaction_with_signature* serialize_transaction_with_signature(Transaction transaction);
	serialized_transaction_without_signature* serialize_transaction_without_signature(Transaction transaction);
}

#endif