#ifndef TRANSACTION_TRANSACTION_INPUT_H
#define TRANSACTION_TRANSACTION_INPUT_H

#include <string>
#include <nlohmann/json.hpp>

namespace transaction {
	class TransactionInput {
	private:
		std::string transaction_hash_;
		int output_index_;

	public:
		TransactionInput(nlohmann::json transaction_input_json);
	};
}

#endif