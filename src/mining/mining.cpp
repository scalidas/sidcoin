#include <cstdint>

#include "mining/mining.h"
#include "block/block.h"

//Basic single threaded mining implementation
void mining::mine_block(block::Block& block) {
	uint32_t nonce = 0;
	block.setNonce(nonce);

	while (!block.checkNonce()) {
		if (nonce == UINT32_MAX) {
			throw std::exception("No possible nonce discovered");
		}

		block.setNonce(++nonce);
	}

	return;
}