#ifndef VALIDATION_VALIDATION_H
#define VALIDATION_VALIDATION_H

#include "block/block.h"
#include "transaction/transaction.h"

namespace validation {
	bool validate_newly_recieved_block(block::Block block);

	bool validate_single_transaction(transaction::Transaction transaction);
}
#endif