#ifndef CRYPTO_ECDSA_H
#define CRYPTO_ECDSA_H

#include <iostream>
#include <string>
#include <memory>
#include <optional>
#include <array>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>

#include "constants.h"
#include "crypto/sha256.h"

namespace transaction {
    struct serialized_transaction_without_signature;
}

namespace crypto {
    struct EC_KEY_Deleter {
        void operator()(EC_KEY* key) const {
            if (key) EC_KEY_free(key);
        }
    };
    using eckey_ptr = std::unique_ptr<EC_KEY, EC_KEY_Deleter>;

    struct ECDSA_SIG_Deleter {
        void operator()(ECDSA_SIG* sig) const {
            if (sig) ECDSA_SIG_free(sig);
        }
    };
    using ecdsa_sig_ptr = std::unique_ptr<ECDSA_SIG, ECDSA_SIG_Deleter>;

    const std::string DEFAULT_PRIVATE_KEY_FILE = "sidcoin_files/SIDCOIN_ecdsa_secp256k1_private_key.pem";
    const std::string DEFAULT_PUBLIC_KEY_FILE = "sidcoin_files/SIDCOIN_ecdsa_secp256k1_public_key.pem";

    class ECDSASignature {
    public:
        ECDSASignature() = default;
        ECDSASignature(const ECDSASignature& other);
        ECDSASignature& operator=(const ECDSASignature& other);
        ECDSASignature(ECDSASignature&&) noexcept = default;
        ECDSASignature& operator=(ECDSASignature&&) noexcept = default;

        static std::optional<ECDSASignature> fromHexStrings(const std::string& r_str, const std::string& s_str);
        std::optional<std::string> rHex() const;
        std::optional<std::string> sHex() const;
        bool writeToBuffer(std::array<uint8_t, ECDSA_SIGNATURE_SIZE>& buffer) const;
        bool isValid() const;
        const ECDSA_SIG* get() const;

    private:
        explicit ECDSASignature(ecdsa_sig_ptr signature);
        ecdsa_sig_ptr signature_;
        friend class ECDSAKey;
    };

    class ECDSAKey {
    public:
        ECDSAKey() = default;
        ECDSAKey(const ECDSAKey& other);
        ECDSAKey& operator=(const ECDSAKey& other);
        ECDSAKey(ECDSAKey&&) noexcept = default;
        ECDSAKey& operator=(ECDSAKey&&) noexcept = default;

        static std::optional<ECDSAKey> generateKeyPair();
        static std::optional<ECDSAKey> loadPrivateKeyFromFile(const std::string& filename);
        static std::optional<ECDSAKey> loadPublicKeyFromFile(const std::string& filename);
        static std::optional<ECDSAKey> loadPublicKeyFromString(const std::string& public_key);

        bool savePrivateKey(const std::string& filename) const;
        bool savePublicKey(const std::string& filename) const;

        std::optional<ECDSASignature> signHash(const SHA256Hash& message_hash) const;
        std::optional<ECDSASignature> signTransaction(const transaction::serialized_transaction_without_signature& message) const;

        bool verifySignature(const ECDSASignature& signature, const SHA256Hash& message_hash) const;
        bool writePublicKeyToBuffer(std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED>& buffer) const;

        const EC_KEY* get() const;
        bool isValid() const;

    private:
        explicit ECDSAKey(eckey_ptr key);
        eckey_ptr key_;
    };
}

#endif