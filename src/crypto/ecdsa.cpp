#include <iostream>
#include <string>
#include <sstream>
#include <array>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include "crypto/sha256.h"
#include "crypto/ecdsa.h"

//Generate and return OpenSSH ecdsa key
EC_KEY* crypto::generate_ecdsa_key_pair() {
    int ret;
    ECDSA_SIG* sig;
    EC_KEY* eckey;
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1);

    if (eckey == NULL)
    {
        return NULL;
    }
    if (!EC_KEY_generate_key(eckey))
    {
        EC_KEY_free(eckey);
        return NULL;
    }

    return eckey;
    
}

//Save generated private key to file
bool crypto::save_ec_private_key(const EC_KEY* eckey, const std::string& filename) {
    if (!eckey) {
        return false;
    }

    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        return false;
    }

    bool success = PEM_write_bio_ECPrivateKey(bio, const_cast<EC_KEY*>(eckey), nullptr, nullptr, 0, nullptr, nullptr);

    BIO_free(bio);
    return success;
}

//Save generated public key to file
bool crypto::save_ec_public_key(const EC_KEY* eckey, const std::string& filename) {
    if (!eckey) {
        return false;
    }

    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        return false;
    }

    bool success = PEM_write_bio_EC_PUBKEY(bio, eckey);

    BIO_free(bio);
    return success;
}

//Free ec key
void crypto::free_ec_key(const EC_KEY* eckey) {
    EC_KEY_free(const_cast<EC_KEY*>(eckey));
}

void crypto::free_ecdsa_sig(const ECDSA_SIG* signature) {
    ECDSA_SIG_free(const_cast<ECDSA_SIG*>(signature));
}

//Sign a string message
ECDSA_SIG* crypto::sign_message(const std::string& message, EC_KEY* eckey) {
    int ret = 0;
    std::vector<unsigned char> hash = crypto::sha256(message, ret);
    if (ret == -1) {
        return NULL;
    }

    ECDSA_SIG* signature = ECDSA_do_sign(reinterpret_cast<const unsigned char*>(message.c_str()), message.length() + 1, eckey);
    return signature;
}

//Verify that a signature is valid for the given message
int crypto::verify_signature_string(const std::string& message, ECDSA_SIG* signature, EC_KEY* eckey) {

    return ECDSA_do_verify(reinterpret_cast<const unsigned char*>(message.c_str()), message.length() + 1, signature, eckey);
}

//Verify that a signature is valid for the given message
int crypto::verify_signature_hash(const std::array<unsigned char, SHA256_HASH_SIZE> message, ECDSA_SIG* signature, EC_KEY* eckey) {
   
    return ECDSA_do_verify(reinterpret_cast<const unsigned char*>(message.data()), message.size(), signature, eckey);
}

//Load private key from PEM file
int crypto::load_ecdsa_private_key_from_file(const std::string& filename, EC_KEY* eckey) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (bio == NULL) {
        return -1;
    }

    EC_KEY* ec_priv_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    if (ec_priv_key == NULL) {
        BIO_free_all(bio);
        return -1;
    }

    if (EC_KEY_set_private_key(eckey, EC_KEY_get0_private_key(ec_priv_key)) != 1) {
        BIO_free_all(bio);
        crypto::free_ec_key(ec_priv_key);
        return -1;
    }

    BIO_free_all(bio);
    crypto::free_ec_key(ec_priv_key);

    return 0;

}

//Load private key from PEM file
int crypto::load_ecdsa_public_key_from_file(const std::string& filename, EC_KEY* eckey) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (bio == NULL) {
        return -1;
    }

    EC_KEY* ec_pub_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    if (ec_pub_key == NULL) {
        BIO_free_all(bio);
        return -2;
    }

    if (EC_KEY_set_public_key(eckey, EC_KEY_get0_public_key(ec_pub_key)) != 1) {
        BIO_free_all(bio);
        crypto::free_ec_key(ec_pub_key);
        return -3;
    }

    BIO_free_all(bio);
    crypto::free_ec_key(ec_pub_key);

    return 0;

}

//Load private key from PEM file
int crypto::load_ecdsa_public_key_from_string(const std::string& public_key, EC_KEY* eckey) {
    BIO* bio = BIO_new_mem_buf(public_key.data(), public_key.size());
    if (bio == NULL) {
        return -1;
    }

    EC_KEY* ec_pub_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    if (ec_pub_key == NULL) {
        BIO_free_all(bio);
        return -2;
    }

    if (EC_KEY_set_public_key(eckey, EC_KEY_get0_public_key(ec_pub_key)) != 1) {
        BIO_free_all(bio);
        crypto::free_ec_key(ec_pub_key);
        return -3;
    }

    BIO_free_all(bio);
    crypto::free_ec_key(ec_pub_key);

    return 0;

}

//Return r value as a string representing its hex
std::string crypto::ecdsa_signature_r_as_hex_string(ECDSA_SIG* signature) {
    char* r_cstr = BN_bn2hex(ECDSA_SIG_get0_r(signature));
    if (r_cstr == NULL) {
        return std::string();
    }


    std::string result = std::string(r_cstr);
    OPENSSL_free(r_cstr);
    return result;
}

//Return s value as a string representing it in hex
std::string crypto::ecdsa_signature_s_as_hex_string(ECDSA_SIG* signature) {
    char* s_cstr = BN_bn2hex(ECDSA_SIG_get0_s(signature));
    if (s_cstr == NULL) {
        return std::string();
    }

    std::string result = std::string(s_cstr);
    OPENSSL_free(s_cstr);
    return result;
}

//Reconstruct a signature from hex strings represneting r and s
ECDSA_SIG* crypto::ecdsa_signature_from_hex_strings(const std::string& r_str, const std::string& s_str) {
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;


    int ret = BN_hex2bn(&r, r_str.c_str());
    if (ret != r_str.size() || r == NULL) {
        return NULL;
    }

    ret = BN_hex2bn(&s, s_str.c_str());
    if (ret != s_str.size() || s == NULL) {
        BN_free(r);
        return NULL;
    }

    ECDSA_SIG* signature = ECDSA_SIG_new();
    if (signature == NULL) {
        throw std::bad_alloc();
    }

    ret = ECDSA_SIG_set0(signature, r, s);
    if (ret != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(signature);
        return NULL;
    }

    return signature;
}

//Write the raw public key to a buffer. Return 0 on success
int crypto::write_public_key_to_buffer(EC_KEY* ec_key, std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED>& buffer) {
    //Find required buffer length for this representation
    const EC_POINT* public_point = EC_KEY_get0_public_key(ec_key);
    if (!public_point) {
        return -1;
    }

    size_t key_len = EC_POINT_point2oct(
        EC_KEY_get0_group(ec_key), // Get the EC_GROUP from the EC_KEY
        public_point,
        POINT_CONVERSION_UNCOMPRESSED, // We want the uncompressed format
        nullptr, // Pass NULL to get the required length
        0,       // Pass 0 for length when buf is NULL
        nullptr  // BN_CTX can be NULL for this operation
    );

    if (key_len != buffer.size()) {
        return -1;
    }

    if (EC_POINT_point2oct(EC_KEY_get0_group(ec_key), public_point, POINT_CONVERSION_UNCOMPRESSED,
        buffer.data(), key_len, NULL) == 0) {
        return -1;
    }

    return 0;
}

int crypto::write_signature_to_buffer(ECDSA_SIG* signature, std::array<uint8_t, ECDSA_SIGNATURE_SIZE>& buffer) {
    const BIGNUM* signature_r = NULL;
    const BIGNUM* signature_s = NULL;

    ECDSA_SIG_get0(signature, &signature_r, &signature_s);
    if (signature_r == NULL || signature_s == NULL) {
        return -1;
    }

    int size_r = BN_num_bytes(signature_r);
    int size_s = BN_num_bytes(signature_s);

    if (size_r > ECDSA_SIGNATURE_SIZE / 2 || size_s > ECDSA_SIGNATURE_SIZE / 2) {
        return -1;
    }

    if ((BN_bn2bin(signature_r, buffer.data()) != size_r) || (BN_bn2bin(signature_s, buffer.data() + ECDSA_SIGNATURE_SIZE / 2) != size_s)) {
        return -1;
    }

    return 0;
}