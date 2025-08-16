#ifndef CRYPTO_ECDSA_H
#define CRYPTO_ECDSA_H

#include <iostream>
#include <string>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>

#include "sidcoin_constants.h"
#include "crypto/sha256.h"

namespace crypto {
    const std::string DEFAULT_PRIVATE_KEY_FILE = "SIDCOIN_ecdsa_secp256k1_private_key.pem";
    const std::string DEFAULT_PUBLIC_KEY_FILE = "SIDCOIN_ecdsa_secp256k1_public_key.pem";

    EC_KEY* generate_ecdsa_key_pair();

    bool save_ec_private_key(const EC_KEY* eckey, const std::string& filename);

    bool save_ec_public_key(const EC_KEY* eckey, const std::string& filename);

    void free_ec_key(const EC_KEY* eckey);

    void free_ecdsa_sig(const ECDSA_SIG* signature);

    ECDSA_SIG* sign_message(const std::string& message, EC_KEY* eckey);

    int verify_signature_string(const std::string& message, ECDSA_SIG* signature, EC_KEY* eckey);

    int verify_signature_hash(const std::array<unsigned char, SHA256_HASH_SIZE> message, ECDSA_SIG* signature, EC_KEY* eckey);

    int load_ecdsa_private_key_from_file(const std::string& filename, EC_KEY* eckey);

    int load_ecdsa_public_key_from_file(const std::string& filename, EC_KEY* eckey);

    int load_ecdsa_public_key_from_string(const std::string& publickey, EC_KEY* eckey);

    std::string ecdsa_signature_r_as_hex_string(ECDSA_SIG* signature);

    std::string ecdsa_signature_s_as_hex_string(ECDSA_SIG* signature);

    ECDSA_SIG* ecdsa_signature_from_hex_strings(const std::string& r_str, const std::string& s_str);

    int write_public_key_to_buffer(EC_KEY* ec_key, std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED>& buffer);

    int write_signature_to_buffer(ECDSA_SIG* signature, std::array<uint8_t, ECDSA_SIGNATURE_SIZE>& buffer);

}
#endif