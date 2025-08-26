#ifndef MINING_MINING_H
#define MINING_MINING_H

#include "block/block.h"
#include "sidcoin_constants.h"

namespace mining {

	//Test different nonces until suitable nonce is found, keyboard interrupt, or no nonce produces correct result
	void mine_block(block::Block& block);
}

#endif