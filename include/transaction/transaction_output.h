#ifndef TRANSACTION_TRANSACTION_OUTPUT_H
#define TRANSACTION_TRANSACTION_OUTPUT_H

#include <string>
#include <nlohmann/json.hpp>

namespace transaction {
	class TransactionOutput {
	private:
		std::string transaction_hash_;
		double amount_;

	public:
		TransactionOutput(nlohmann::json transaction_output_json);
		TransactionOutput();
	};
}

#endif