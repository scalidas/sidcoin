#include <cstring>

#include "nlohmann/json.hpp"

#include "block/block.h"
#include "transaction/transaction.h"
#include "utilities/timestamps.h"
#include "utilities/miscellaneous.h"
#include "constants.h"
#include "crypto/sha256.h"

block::Block::Block(nlohmann::json block_json) {
    sidcoin_version_ = block_json["sidcoin_version"];
    index_ = block_json["index"];
    timestamp_ = utilities::parse_utc_timestamp_str(block_json["timestamp"]);

    int num_transactions = block_json["transactions"].size();
    if (num_transactions != NUM_TRANSACTIONS_PER_BLOCK) {
        throw std::runtime_error("Incorrect number of transactions");
    }

    for (int i = 0; i < num_transactions; i++) {
        auto tx_opt = transaction::Transaction::from_json(block_json["transactions"][i]);
        transaction::Transaction tx = tx_opt.value();
        transactions_.push_back(std::move(tx));
    }

    nonce_ = block_json["nonce"];

    std::vector<uint8_t> prev_hash_vec = utilities::hex_string_to_bytes(block_json["prev_hash"]);
    if (prev_hash_vec.size() != SHA256_HASH_SIZE) {
        throw std::runtime_error("Error loading hash");
    }

    std::copy(prev_hash_vec.begin(), prev_hash_vec.end(), prev_hash_.begin());
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

void block::Block::setNonce(int nonce) {
    nonce_ = nonce;
}

bool block::operator<(const block::Block& left, const block::Block& right) {
    return left.nonce_ < right.nonce_;
}

bool block::Block::checkNonce() const {
    auto serialized_bk_opt = serialize_block(*this);
    if (!serialized_bk_opt) {
        return false;
    }

    auto hash_opt = crypto::SHA256Hash::hash(*serialized_bk_opt);
    if (!hash_opt) {
        return false;
    }

    for (int i = 0; i < NUM_LEADING_ZEROS_HASH; i++) {
        if (hash_opt->data()[i] != 0) {
            return false;
        }
    }

    return true;
}

std::optional<block::serialized_block> block::serialize_block(const block::Block& block) {
    serialized_block serialized_bk;
    serialized_bk.prev_hash = block.prev_hash_;

    utilities::write_timestamp_to_buffer(block.timestamp_, serialized_bk.timestamp);
    std::memcpy(serialized_bk.nonce.data(), &block.nonce_, NONCE_SIZE);

    auto tx1 = block.transactions_[0].serialize_transaction_with_signature();
    if (!tx1) {
        return std::nullopt;
    }

    auto tx2 = block.transactions_[1].serialize_transaction_with_signature();
    if (!tx2) {
        return std::nullopt;
    }

    auto tx3 = block.transactions_[2].serialize_transaction_with_signature();
    if (!tx3) {
        return std::nullopt;
    }

    serialized_bk.tx1 = *tx1;
    serialized_bk.tx2 = *tx2;
    serialized_bk.tx3 = *tx3;

    return serialized_bk;
}
