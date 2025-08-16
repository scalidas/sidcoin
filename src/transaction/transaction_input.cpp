#include <string>
#include "transaction/transaction_input.h"

transaction::TransactionInput::TransactionInput(nlohmann::json transaction_input_json) {
	transaction_hash_ = transaction_input_json["transaction_hash"];
	output_index_ = transaction_input_json["output_index"];
}