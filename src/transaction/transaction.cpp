#include "nlohmann/json.hpp"
#include <stdexcept>
#include <openssl/ec.h>
#include <vector>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "crypto/ecdsa.h"
#include "crypto/sha256.h"

#include "transaction/transaction.h"
#include "utilities/timestamps.h"

std::optional<transaction::Transaction> transaction::Transaction::from_json(const nlohmann::json& transaction_json) {
	try {
		if (!transaction_json.is_object()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("type") || transaction_json["type"] != "transaction") {
			return std::nullopt;
		}

		if (!transaction_json.contains("sidcoin_version") || !transaction_json["sidcoin_version"].is_string()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("timestamp") || !transaction_json["timestamp"].is_string()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("sender_public_key") || !transaction_json["sender_public_key"].is_string()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("receiver_public_key") || !transaction_json["receiver_public_key"].is_string()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("amount") || !transaction_json["amount"].is_number()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("nonce") || !transaction_json["nonce"].is_number_unsigned()) {
			return std::nullopt;
		}

		if (!transaction_json.contains("sender_signature") || !transaction_json["sender_signature"].is_object()) {
			return std::nullopt;
		}

		const auto& signature_json = transaction_json["sender_signature"];
		if (!signature_json.contains("r") || !signature_json["r"].is_string()) {
			return std::nullopt;
		}
		if (!signature_json.contains("s") || !signature_json["s"].is_string()) {
			return std::nullopt;
		}

		double amount = transaction_json["amount"].get<double>();
		uint32_t nonce = transaction_json["nonce"].get<uint32_t>();
		std::string sidcoin_version = transaction_json["sidcoin_version"].get<std::string>();
		std::string timestamp_str = transaction_json["timestamp"].get<std::string>();
		std::string sender_pub = transaction_json["sender_public_key"].get<std::string>();
		std::string receiver_pub = transaction_json["receiver_public_key"].get<std::string>();
		std::string r_hex = signature_json["r"].get<std::string>();
		std::string s_hex = signature_json["s"].get<std::string>();

		auto sender_opt = crypto::ECDSAKey::loadPublicKeyFromString(sender_pub);
		if (!sender_opt) {
			return std::nullopt;
		}

		auto receiver_opt = crypto::ECDSAKey::loadPublicKeyFromString(receiver_pub);
		if (!receiver_opt) {
			return std::nullopt;
		}

		auto sig_opt = crypto::ECDSASignature::fromHexStrings(r_hex, s_hex);
		if (!sig_opt) {
			return std::nullopt;
		}

		Transaction tx(std::move(*sender_opt), std::move(*receiver_opt), amount, nonce);
		tx.sidcoin_version_ = std::move(sidcoin_version);
		tx.timestamp_ = utilities::parse_utc_timestamp_str(timestamp_str);
		tx.sender_signature_ = std::move(*sig_opt);
		return tx;
	}
	catch (const std::exception&) {
		return std::nullopt;
	}
}

nlohmann::json transaction::Transaction::toJSON() const {
	using namespace std;
	nlohmann::json j;
	j["sidcoin_version"] = sidcoin_version_;
	j["type"] = "transaction";
	j["timestamp"] = utilities::get_utc_timestamp_str(timestamp_);

	auto keyToPem = [](const crypto::ECDSAKey& key)->optional<string> {
		if (!key.isValid()) return nullopt;
		BIO* bio = BIO_new(BIO_s_mem());
		if (!bio) return nullopt;
		if (!PEM_write_bio_EC_PUBKEY(bio, key.get())) {
			BIO_free(bio);
			return nullopt;
		}
		char* data = nullptr;
		long len = BIO_get_mem_data(bio, &data);
		string s;
		if (len > 0 && data) s.assign(data, data + len);
		BIO_free(bio);
		return s;
		};

	auto sender_pem = keyToPem(sender_public_key_);
	auto receiver_pem = keyToPem(receiver_public_key_);

	j["sender_public_key"] = sender_pem ? *sender_pem : string();
	j["receiver_public_key"] = receiver_pem ? *receiver_pem : string();

	j["amount"] = amount_;
	j["nonce"] = nonce_;

	nlohmann::json sig;
	auto r = sender_signature_.rHex();
	auto s = sender_signature_.sHex();
	sig["r"] = r ? *r : string();
	sig["s"] = s ? *s : string();
	j["sender_signature"] = sig;

	return j;
}


//Later - will need to check if the user had sufficient balance to make the transaction
bool transaction::Transaction::isValid() const {
	if (!sender_signature_.isValid()) {
		return false;
	}

	auto serialized_tx_no_sig_opt = serialize_transaction_without_signature();
	if (!serialized_tx_no_sig_opt) {
		return false;
	}

	auto hash = crypto::SHA256Hash::hash(*serialized_tx_no_sig_opt);
	if (!hash) {
		throw std::runtime_error("Problem validating transaction");
	}

	return sender_public_key_.verifySignature(sender_signature_, *hash);
}

std::optional<transaction::serialized_transaction_with_signature> transaction::Transaction::serialize_transaction_with_signature() const {
	serialized_transaction_with_signature serialized_tx;
	serialized_tx.nonce = nonce_;

	if (!sender_public_key_.writePublicKeyToBuffer(serialized_tx.sender_public_key)) {
		return std::nullopt;
	}
	if (!receiver_public_key_.writePublicKeyToBuffer(serialized_tx.receiver_public_key)) {
		return std::nullopt;
	}

	std::memcpy(serialized_tx.amount.data(), &amount_, sizeof(double));

	if (!sender_signature_.writeToBuffer(serialized_tx.signature)) {
		return std::nullopt;
	}

	return serialized_tx;
}

std::optional<transaction::serialized_transaction_without_signature> transaction::Transaction::serialize_transaction_without_signature() const {
	serialized_transaction_without_signature serialized_tx;
	serialized_tx.nonce = nonce_;

	if (!sender_public_key_.writePublicKeyToBuffer(serialized_tx.sender_public_key)) {
		return std::nullopt;
	}
	if (!receiver_public_key_.writePublicKeyToBuffer(serialized_tx.receiver_public_key)) {
		return std::nullopt;
	}

	std::memcpy(serialized_tx.amount.data(), &amount_, sizeof(double));
	return serialized_tx;
}