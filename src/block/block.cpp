#include <cstring>

#include "nlohmann/json.hpp"

#include "block/block.h"
#include "transaction/transaction.h"
#include "utilities/timestamps.h"
#include "utilities/miscellaneous.h"
#include "sidcoin_constants.h"

block::Block::Block(nlohmann::json block_json) {
	sidcoin_version_ = block_json["sidcoin_version"];
	index_ = block_json["index"];
	timestamp_ = utilities::parse_utc_timestamp_str(block_json["timestamp"]);
	
	int num_transactions = block_json["transactions"].size();
	if (num_transactions != NUM_TRANSACTIONS_PER_BLOCK) {
		throw std::exception("Incorrect number of transactions");
	}

	for (int i = 0; i < num_transactions; i++) {
		transaction::Transaction tx = transaction::Transaction(block_json["transactions"][i]);
		transactions_.push_back(tx);
	}

	nonce_ = block_json["nonce"];


	std::vector prev_hash_vec = utilities::hex_string_to_bytes(block_json["prev_hash"]);
	if (prev_hash_vec.size() != SHA256_HASH_SIZE) {
		throw std::exception("Error loading hash");
	}
}

bool block::Block::isValid() {
	//Check that number of transactions is correct
	if (transactions_.size() != NUM_TRANSACTIONS_PER_BLOCK) {
		return false;
	}

	//Check that first transaction is valid
	if (transactions_[0].amount_ != MINING_REWARD) {
		return false;
	}

	//Check sender of first transactions is all 0
	std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED> buffer;
	crypto::write_public_key_to_buffer(transactions_[0].sender_public_key_, buffer);
	for (uint8_t byte : buffer) {
		if (byte != 0) {
			return false;
		}
	}
	
	//Check that all transactions are valid
	for (transaction::Transaction tx: transactions_) {
		if (!tx.isValid()) {
			return false;
		}
	}

	//Check that serialized hash contains correct number of leading zeros
	checkNonce();
}

void block::Block::setNonce(int nonce) {
	nonce_ = nonce;
}

bool block::Block::checkNonce() {
	serialized_block* serialized_bk = serialize_block(*this);

	int ret = 0;
	std::array<unsigned char, SHA256_DIGEST_LENGTH> hash = crypto::sha256_block(serialized_bk, ret);
	if (ret != 0) {
		return false;
	}

	delete serialized_bk;

	for (int i = 0; i < NUM_LEADING_ZEROS_HASH; i++) {
		if (hash[i] != 0) {
			return false;
		}
	}

	return true;
}

block::serialized_block* block::serialize_block(const block::Block& block) {
	serialized_block* serialized_bk = new serialized_block();

	serialized_bk->prev_hash = block.prev_hash_;
	
	utilities::write_timestamp_to_buffer(block.timestamp_, serialized_bk->timestamp);

	std::memcpy(&(serialized_bk->nonce), &block.nonce_, NONCE_SIZE);

	transaction::serialized_transaction_with_signature* tx1 = serialize_transaction_with_signature(block.transactions_[0]);
	if (tx1 == NULL) {
		delete serialized_bk;
		return NULL;
	}

	transaction::serialized_transaction_with_signature* tx2 = serialize_transaction_with_signature(block.transactions_[1]);
	if (tx2 == NULL) {
		delete serialized_bk;
		delete tx1;
		return NULL;
	}
	
	transaction::serialized_transaction_with_signature* tx3 = serialize_transaction_with_signature(block.transactions_[2]);
	if (tx3 == NULL) {
		delete serialized_bk;
		delete tx1;
		delete tx2;
		return NULL;
	}
	

	serialized_bk->tx1 = *(tx1);
	serialized_bk->tx2 = *(tx2);
	serialized_bk->tx3 = *(tx3);

	delete tx1;
	delete tx2;
	delete tx3;

	return serialized_bk;
}