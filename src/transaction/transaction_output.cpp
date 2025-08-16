#include <string>
#include "transaction/transaction_output.h"

transaction::TransactionOutput::TransactionOutput(nlohmann::json transaction_output_json) {
	transaction_hash_ = transaction_output_json["transaction_hash"];
	amount_ = transaction_output_json["amount"];
}

transaction::TransactionOutput::TransactionOutput() {
	transaction_hash_ = "";
	amount_ = 0;
}