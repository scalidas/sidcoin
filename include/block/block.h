#ifndef BLOCK_BLOCK_H
#define BLOCK_BLOCK_H

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "constants.h"
#include "transaction/transaction.h"

namespace blockchain {
class Blockchain;
}

namespace block {
struct serialized_block {
    std::array<unsigned char, SHA256_HASH_SIZE> prev_hash;
    std::array<unsigned char, SERIALIZED_TIMESTAMP_SIZE> timestamp;
    uint32_t nonce;

    std::array<transaction::serialized_transaction_with_signature, NUM_TRANSACTIONS_PER_BLOCK> transactions;
};

class Block {
  private:
    std::string sidcoin_version_;
    std::chrono::system_clock::time_point timestamp_;

    uint64_t height_;
    std::vector<transaction::Transaction> transactions_;
    uint32_t nonce_;

    crypto::SHA256Hash prev_hash_;

  public:
    Block(std::string sidcoin_version_, std::chrono::system_clock::time_point timestamp_, uint64_t height,
          std::vector<transaction::Transaction> transactions, uint32_t nonce_, crypto::SHA256Hash prev_hash_)
        : sidcoin_version_(sidcoin_version_), timestamp_(timestamp_), height_(height),
          transactions_(transactions), nonce_(nonce_), prev_hash_(prev_hash_) {}

    Block(uint64_t height, std::vector<transaction::Transaction> transactions, uint32_t nonce_,
          crypto::SHA256Hash prev_hash_)
        : sidcoin_version_(SIDCOIN_VERSION), timestamp_(std::chrono::system_clock::now()), height_(height),
          transactions_(transactions), nonce_(nonce_), prev_hash_(prev_hash_) {}

    static std::optional<Block> from_json(nlohmann::json block_json);

    nlohmann::json toJSON();

    bool isValid() const;

    // Methods for mining
    void setNonce(uint32_t nonce);
    bool checkNonce() const;

    std::optional<serialized_block> serialize_block() const;

    friend class blockchain::Blockchain;
};

} // namespace block

#endif