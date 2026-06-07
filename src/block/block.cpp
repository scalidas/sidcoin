#include <cstring>

#include "nlohmann/json.hpp"

#include "block/block.h"
#include "transaction/transaction.h"
#include "utilities/timestamps.h"
#include "utilities/miscellaneous.h"
#include "constants.h"
#include "crypto/sha256.h"

std::optional<block::Block> block::Block::from_json(nlohmann::json block_json) {
	try {
		if (!block_json.is_object()) {
			return std::nullopt;
		}

		if (!block_json.contains("type") || block_json["type"] != "block") {
			return std::nullopt;
		}

		if (!block_json.contains("sidcoin_version") || !block_json["sidcoin_version"].is_string()) {
			return std::nullopt;
		}

		if (!block_json.contains("timestamp") || !block_json["timestamp"].is_string()) {
			return std::nullopt;
		}

		if (!block_json.contains("transactions") || !block_json["transactions"].is_array()) {
			return std::nullopt;
		}

		if (static_cast<int>(block_json["transactions"].size()) != NUM_TRANSACTIONS_PER_BLOCK) {
			return std::nullopt;
		}

		if (!block_json.contains("nonce") || !block_json["nonce"].is_number_unsigned()) {
			return std::nullopt;
		}

		if (!block_json.contains("prev_hash") || !block_json["prev_hash"].is_string()) {
			return std::nullopt;
		}

		std::string sidcoin_version = block_json["sidcoin_version"].get<std::string>();
		std::string timestamp_str = block_json["timestamp"].get<std::string>();
		uint32_t nonce = block_json["nonce"].get<uint32_t>();
		std::string prev_hash_hex = block_json["prev_hash"].get<std::string>();

		auto timestamp = utilities::parse_utc_timestamp_str(timestamp_str);

		std::vector<transaction::Transaction> transactions;
		for (const auto& tx_json : block_json["transactions"]) {
			auto tx_opt = transaction::Transaction::from_json(tx_json);
			if (!tx_opt) {
				return std::nullopt;
			}
			transactions.push_back(std::move(*tx_opt));
		}

		auto prev_hash_opt = crypto::SHA256Hash::fromHexString(prev_hash_hex);
		if (!prev_hash_opt) {
			return std::nullopt;
		}

		Block block(sidcoin_version, timestamp, 0, std::move(transactions), nonce, std::move(*prev_hash_opt));
		return block;
	} catch (const std::exception&) {
		return std::nullopt;
	}
}

nlohmann::json block::Block::toJSON() {
    using namespace std;
    nlohmann::json j;
    j["sidcoin_version"] = sidcoin_version_;
    j["type"] = "block";
    j["timestamp"] = utilities::get_utc_timestamp_str(timestamp_);

    nlohmann::json txs = nlohmann::json::array();
    for (const auto &tx : transactions_) {
        txs.push_back(tx.toJSON());
    }
    j["transactions"] = txs;

    j["nonce"] = nonce_;
    j["prev_hash"] = prev_hash_.toHexString();

    return j;
}

bool block::Block::isValid() const {
    if (transactions_.size() != NUM_TRANSACTIONS_PER_BLOCK) {
        return false;
    }

    if (transactions_[0].amount_ != MINING_REWARD) {
        return false;
    }

    std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> buffer{};
    if (!transactions_[0].sender_public_key_.writePublicKeyToBuffer(buffer)) {
        return false;
    }

    for (uint8_t byte : buffer) {
        if (byte != 0) {
            return false;
        }
    }

    for (const transaction::Transaction& tx : transactions_) {
        if (!tx.isValid()) {
            return false;
        }
    }

    return checkNonce();
}

void block::Block::setNonce(uint32_t nonce) {
    nonce_ = nonce;
}

//Check that the hash with the nonce satisfies the PoW (tight loop for mining)
bool block::Block::checkNonce() const {
    auto serialized_bk_opt = serialize_block();
    if (!serialized_bk_opt) {
        return false;
    }

    auto hash_opt = crypto::SHA256Hash::hash(*serialized_bk_opt);
    if (!hash_opt) {
        return false;
    }

    int full = NUM_TRAILING_ZEROS_HASH / 8;
    int rem = NUM_TRAILING_ZEROS_HASH % 8;

    for (int i = 0; i < full; i++)
        if (hash_opt->data()[31 - i] != 0)
            return false;

    if (rem) {
        unsigned char mask = (1 << rem) - 1;
        return (hash_opt->data()[31 - full] & mask) == 0;
    }

    return true;
}

std::optional<block::serialized_block> block::Block::serialize_block() const {
    serialized_block serialized_bk;
    
    std::memcpy(&(serialized_bk.prev_hash), prev_hash_.data(), SHA256_HASH_SIZE);

    utilities::write_timestamp_to_buffer(timestamp_, serialized_bk.timestamp);

    serialized_bk.nonce = nonce_;

    auto tx1 = transactions_[0].serialize_transaction_with_signature();
    if (!tx1) {
        return std::nullopt;
    }

    auto tx2 = transactions_[1].serialize_transaction_with_signature();
    if (!tx2) {
        return std::nullopt;
    }

    auto tx3 = transactions_[2].serialize_transaction_with_signature();
    if (!tx3) {
        return std::nullopt;
    }

    serialized_bk.transactions = {tx1.value(), tx2.value(), tx3.value()};

    return serialized_bk;
}
