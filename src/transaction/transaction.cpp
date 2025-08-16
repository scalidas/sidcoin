#include "nlohmann/json.hpp"
#include <stdexcept>
#include <openssl/ecdsa.h>
#include <vector>
#include <openssl/ec.h>
#include "crypto/ecdsa.h"
#include "crypto/sha256.h"

#include "transaction/transaction.h"
#include "transaction/transaction_input.h"
#include "transaction/transaction_output.h"
#include "utilities/timestamps.h"

//Populate a transaction class from JSON
transaction::Transaction::Transaction(nlohmann::json transaction_json) {
	sidcoin_version_ = transaction_json["sidcoin_version"];
	block_index_ = transaction_json["block_index"];

	timestamp_ = utilities::parse_utc_timestamp_str(transaction_json["timestamp"]);
	
	sender_public_key_ = EC_KEY_new_by_curve_name(NID_secp256k1); //Call by this function to populate other fields of the eckey
	if (sender_public_key_ == NULL) {
		throw std::bad_alloc();
		return;
	}

	int ret = crypto::load_ecdsa_public_key_from_string(transaction_json["sender_public_key"], sender_public_key_);
	if (ret != 0) {
		std::cout << "ret" << ret;
		crypto::free_ec_key(sender_public_key_);
		throw std::exception("Unable to load sender public key ");
		return;
	}

	receiver_public_key_ = EC_KEY_new_by_curve_name(NID_secp256k1); //Call by this function to populate other fields of the eckey
	if (receiver_public_key_ == NULL) {
		crypto::free_ec_key(sender_public_key_);
		throw std::bad_alloc();
		return;
	}

	ret = crypto::load_ecdsa_public_key_from_string(transaction_json["receiver_public_key"], receiver_public_key_);
	if (ret != 0) {
		crypto::free_ec_key(sender_public_key_);
		crypto::free_ec_key(receiver_public_key_);
		throw std::exception("Unable to load recieiver public key");
		return;
	}

	amount_ = transaction_json["amount"];
	
	inputs_ = std::vector<transaction::TransactionInput>();
	for (nlohmann::json transaction_input : transaction_json["inputs"]) {
		inputs_.push_back(transaction::TransactionInput(transaction_input));
	}

	output1_ = transaction_json["output1"].empty() ? TransactionOutput() : TransactionOutput(transaction_json["output1"]);
	output2_ = transaction_json["output2"].empty() ? TransactionOutput() : TransactionOutput(transaction_json["output2"]);

	sender_signature_ = crypto::ecdsa_signature_from_hex_strings(transaction_json["sender_signature"]["r"], transaction_json["sender_signature"]["s"]);
	if (sender_signature_ == NULL) {
		crypto::free_ec_key(sender_public_key_);
		crypto::free_ec_key(receiver_public_key_);
		throw std::exception("Unable to load signature");
	}
}

transaction::Transaction::~Transaction() {
	crypto::free_ec_key(sender_public_key_);
	crypto::free_ec_key(receiver_public_key_);
}

transaction::Transaction::Transaction(const Transaction& other)
	: sidcoin_version_(other.sidcoin_version_),
	block_index_(other.block_index_),
	timestamp_(other.timestamp_),       // std::chrono::time_point is copyable
	amount_(other.amount_),
	inputs_(other.inputs_),             // std::vector has its own deep copy
	output1_(other.output1_),           
	output2_(other.output2_)            
{
	sender_public_key_ = EC_KEY_dup(other.sender_public_key_);
	if (sender_public_key_ == NULL) {
		throw std::bad_alloc();
		return;
	}
	
	receiver_public_key_ = EC_KEY_dup(other.receiver_public_key_);
	if (receiver_public_key_ == NULL) {
		crypto::free_ec_key(sender_public_key_);
		throw std::bad_alloc();
		return;
	}

	sender_signature_ = crypto::ecdsa_signature_from_hex_strings(crypto::ecdsa_signature_r_as_hex_string(other.sender_signature_), crypto::ecdsa_signature_s_as_hex_string(other.sender_signature_));
}

transaction::Transaction& transaction::Transaction::operator=(const Transaction& other) {
	if (this == &other) return *this; // self-assignment guard

	sidcoin_version_ = other.sidcoin_version_;
	block_index_ = other.block_index_;
	timestamp_ = other.timestamp_;
	amount_ = other.amount_;
	inputs_ = other.inputs_;
	output1_ = other.output1_;
	output2_ = other.output2_;

	sender_public_key_ = other.sender_public_key_ ? EC_KEY_dup(other.sender_public_key_) : nullptr;
	receiver_public_key_ = other.receiver_public_key_ ? EC_KEY_dup(other.receiver_public_key_) : nullptr;
	sender_signature_ = other.sender_signature_ ? crypto::ecdsa_signature_from_hex_strings(crypto::ecdsa_signature_r_as_hex_string(other.sender_signature_), crypto::ecdsa_signature_s_as_hex_string(other.sender_signature_)) : nullptr;

	return *this;
}

bool transaction::Transaction::isValid() {
	// TODO: Make sure that the inputs of the transaction are unspent
	
	serialized_transaction_without_signature* serialized_tx_no_sig = serialize_transaction_without_signature(*this);

	int ret = 0;
	std::array<unsigned char, SHA256_HASH_SIZE> hash = crypto::sha256_transaction_without_signature(serialized_tx_no_sig, ret);
	if (ret != 0) {
		throw std::exception("Problem validating transaction");
	}

	bool signature_is_valid = crypto::verify_signature_hash(hash, sender_signature_, sender_public_key_);

	delete serialized_tx_no_sig;
	
	return signature_is_valid;
}

//Serialize transaction into a dynamically allocated block - include signature so this is meant for adding to a serialized block
transaction::serialized_transaction_with_signature* transaction::serialize_transaction_with_signature(transaction::Transaction transaction) {
	serialized_transaction_with_signature* serialized_tx = new serialized_transaction_with_signature();
	if (serialized_tx == NULL) {
		return NULL;
	}

	//Put 65 byte public keys into buffer
	if (crypto::write_public_key_to_buffer(transaction.sender_public_key_, serialized_tx->sender_public_key) != 0) {
		delete serialized_tx;
		return NULL;
	}
	if (crypto::write_public_key_to_buffer(transaction.receiver_public_key_, serialized_tx->receiver_public_key) != 0) {
		delete serialized_tx;
		return NULL;
	}

	//Copy amount
	std::memcpy(&(serialized_tx->amount), &transaction.amount_, sizeof(double));

	//Copy signature
	crypto::write_signature_to_buffer(transaction.sender_signature_, serialized_tx->signature);

	return serialized_tx;
}

//Serialize transaction without including signature
transaction::serialized_transaction_without_signature* transaction::serialize_transaction_without_signature(transaction::Transaction transaction) {
	serialized_transaction_without_signature* serialized_tx = new serialized_transaction_without_signature();
	if (serialized_tx == NULL) {
		return NULL;
	}

	//Put 65 byte public keys into buffer
	if (crypto::write_public_key_to_buffer(transaction.sender_public_key_, serialized_tx->sender_public_key) != 0) {
		delete serialized_tx;
		return NULL;
	}
	if (crypto::write_public_key_to_buffer(transaction.receiver_public_key_, serialized_tx->receiver_public_key) != 0) {
		delete serialized_tx;
		return NULL;
	}

	//Copy amount
	std::memcpy(&(serialized_tx->amount), &transaction.amount_, sizeof(double));

	return serialized_tx;
}