#ifndef TRANSACTION_TRANSACTION_H
#define TRANSACTION_TRANSACTION_H

#include <string>
#include <chrono>
#include <optional>

#include <openssl/ec.h>
#include <vector>

#include "nlohmann/json.hpp"

#include "constants.h"
#include "crypto/ecdsa.h"

namespace block {
	class Block;
}

namespace transaction {

	struct serialized_transaction_with_signature {
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> sender_public_key;
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> receiver_public_key;
		std::array<uint8_t, TX_AMOUNT_SIZE> amount;
		uint32_t nonce;
		std::array<uint8_t, ECDSA_SIGNATURE_SIZE> signature;
	};

	struct serialized_transaction_without_signature {
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> sender_public_key;
		std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> receiver_public_key;
		uint32_t nonce;
		std::array<uint8_t, TX_AMOUNT_SIZE> amount;
	};

	class Transaction {

	private:
		std::string sidcoin_version_;
		std::chrono::system_clock::time_point timestamp_;
		crypto::ECDSAKey sender_public_key_;
		crypto::ECDSAKey receiver_public_key_;
		double amount_;
		uint32_t nonce_;

		crypto::ECDSASignature sender_signature_;

	public:
		static std::optional<Transaction> from_json(const nlohmann::json& transaction_json);

		Transaction(crypto::ECDSAKey sender_public_key, crypto::ECDSAKey receiver_public_key, double amount, uint32_t nonce) :
			sender_public_key_(sender_public_key), receiver_public_key_(receiver_public_key), amount_(amount), nonce_(nonce) 
		{ } ;

		Transaction(const Transaction& other) = default;

		~Transaction() = default;
		Transaction& operator=(const Transaction& other) = default;

		nlohmann::json toJSON() const;

		bool isValid() const;

		friend class block::Block;

		std::optional<serialized_transaction_with_signature> serialize_transaction_with_signature() const;
		std::optional<serialized_transaction_without_signature> serialize_transaction_without_signature() const;
	};

}

#endif