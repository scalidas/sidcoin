#include <iostream>
#include <string>
#include <sstream>
#include <array>
#include <optional>
#include <vector>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include "crypto/sha256.h"
#include "crypto/ecdsa.h"
#include "transaction/transaction.h"

crypto::ECDSASignature::ECDSASignature(const ECDSASignature& other) {
    if (other.signature_) {
        const BIGNUM* orig_r = ECDSA_SIG_get0_r(other.signature_.get());
        const BIGNUM* orig_s = ECDSA_SIG_get0_s(other.signature_.get());
        
        BIGNUM* dup_r = BN_dup(orig_r);
        BIGNUM* dup_s = BN_dup(orig_s);
        
        if (!dup_r || !dup_s) {
            if (dup_r) BN_free(dup_r);
            if (dup_s) BN_free(dup_s);
            throw std::bad_alloc();
        }
        
        ECDSA_SIG* new_sig = ECDSA_SIG_new();
        if (!new_sig) {
            BN_free(dup_r);
            BN_free(dup_s);
            throw std::bad_alloc();
        }
        
        if (ECDSA_SIG_set0(new_sig, dup_r, dup_s) != 1) {
            BN_free(dup_r);
            BN_free(dup_s);
            ECDSA_SIG_free(new_sig);
            throw std::bad_alloc();
        }
        
        signature_.reset(new_sig);
    }
}

crypto::ECDSASignature& crypto::ECDSASignature::operator=(const ECDSASignature& other) {
    if (this == &other) return *this;
    if (other.signature_) {
        const BIGNUM* orig_r = ECDSA_SIG_get0_r(other.signature_.get());
        const BIGNUM* orig_s = ECDSA_SIG_get0_s(other.signature_.get());
        
        BIGNUM* dup_r = BN_dup(orig_r);
        BIGNUM* dup_s = BN_dup(orig_s);
        
        if (!dup_r || !dup_s) {
            if (dup_r) BN_free(dup_r);
            if (dup_s) BN_free(dup_s);
            throw std::bad_alloc();
        }
        
        ECDSA_SIG* new_sig = ECDSA_SIG_new();
        if (!new_sig) {
            BN_free(dup_r);
            BN_free(dup_s);
            throw std::bad_alloc();
        }
        
        if (ECDSA_SIG_set0(new_sig, dup_r, dup_s) != 1) {
            BN_free(dup_r);
            BN_free(dup_s);
            ECDSA_SIG_free(new_sig);
            throw std::bad_alloc();
        }
        
        signature_.reset(new_sig);
    } else {
        signature_.reset();
    }
    return *this;
}

crypto::ECDSASignature::ECDSASignature(ecdsa_sig_ptr signature)
    : signature_(std::move(signature)) {
}

bool crypto::ECDSASignature::isValid() const {
    return signature_ != nullptr;
}

const ECDSA_SIG* crypto::ECDSASignature::get() const {
    return signature_.get();
}

std::optional<std::string> crypto::ECDSASignature::rHex() const {
    if (!signature_) return std::nullopt;
    char* r_cstr = BN_bn2hex(ECDSA_SIG_get0_r(signature_.get()));
    if (r_cstr == NULL) {
        return std::nullopt;
    }

    std::string result(r_cstr);
    OPENSSL_free(r_cstr);
    return result;
}

std::optional<std::string> crypto::ECDSASignature::sHex() const {
    if (!signature_) return std::nullopt;
    char* s_cstr = BN_bn2hex(ECDSA_SIG_get0_s(signature_.get()));
    if (s_cstr == NULL) {
        return std::nullopt;
    }

    std::string result(s_cstr);
    OPENSSL_free(s_cstr);
    return result;
}

bool crypto::ECDSASignature::writeToBuffer(std::array<uint8_t, ECDSA_SIGNATURE_SIZE>& buffer) const {
    if (!signature_) return false;

    const BIGNUM* signature_r = NULL;
    const BIGNUM* signature_s = NULL;
    ECDSA_SIG_get0(signature_.get(), &signature_r, &signature_s);
    if (signature_r == NULL || signature_s == NULL) {
        return false;
    }

    int size_r = BN_num_bytes(signature_r);
    int size_s = BN_num_bytes(signature_s);

    if (size_r > ECDSA_SIGNATURE_SIZE / 2 || size_s > ECDSA_SIGNATURE_SIZE / 2) {
        return false;
    }

    if ((BN_bn2bin(signature_r, buffer.data()) != size_r) || (BN_bn2bin(signature_s, buffer.data() + ECDSA_SIGNATURE_SIZE / 2) != size_s)) {
        return false;
    }

    return true;
}

std::optional<crypto::ECDSASignature> crypto::ECDSASignature::fromHexStrings(const std::string& r_str, const std::string& s_str) {
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;

    int ret = BN_hex2bn(&r, r_str.c_str());
    if (ret != static_cast<int>(r_str.size()) || r == NULL) {
        return std::nullopt;
    }

    ret = BN_hex2bn(&s, s_str.c_str());
    if (ret != static_cast<int>(s_str.size()) || s == NULL) {
        BN_free(r);
        return std::nullopt;
    }

    ECDSA_SIG* signature = ECDSA_SIG_new();
    if (signature == NULL) {
        BN_free(r);
        BN_free(s);
        return std::nullopt;
    }

    crypto::ecdsa_sig_ptr sig_ptr(signature);
    ret = ECDSA_SIG_set0(sig_ptr.get(), r, s);
    if (ret != 1) {
        BN_free(r);
        BN_free(s);
        return std::nullopt;
    }

    return ECDSASignature(std::move(sig_ptr));
}

crypto::ECDSAKey::ECDSAKey(const ECDSAKey& other) {
    if (other.key_) {
        EC_KEY* new_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!new_key) {
            throw std::bad_alloc();
        }

        const EC_POINT* pub_key = EC_KEY_get0_public_key(other.key_.get());
        if (pub_key) {
            EC_POINT* dup_pub = EC_POINT_dup(pub_key, EC_KEY_get0_group(other.key_.get()));
            if (!dup_pub) {
                EC_KEY_free(new_key);
                throw std::bad_alloc();
            }
            if (!EC_KEY_set_public_key(new_key, dup_pub)) {
                EC_POINT_free(dup_pub);
                EC_KEY_free(new_key);
                throw std::bad_alloc();
            }
            EC_POINT_free(dup_pub);
        }

        key_.reset(new_key);
    }
}

crypto::ECDSAKey& crypto::ECDSAKey::operator=(const ECDSAKey& other) {
    if (this == &other) return *this;
    if (other.key_) {
        EC_KEY* new_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!new_key) {
            throw std::bad_alloc();
        }
        
        const EC_POINT* pub_key = EC_KEY_get0_public_key(other.key_.get());
        if (pub_key) {
            EC_POINT* dup_pub = EC_POINT_dup(pub_key, EC_KEY_get0_group(other.key_.get()));
            if (!dup_pub) {
                EC_KEY_free(new_key);
                throw std::bad_alloc();
            }
            if (!EC_KEY_set_public_key(new_key, dup_pub)) {
                EC_POINT_free(dup_pub);
                EC_KEY_free(new_key);
                throw std::bad_alloc();
            }
            EC_POINT_free(dup_pub);
        }
        
        key_.reset(new_key);
    } else {
        key_.reset();
    }
    return *this;
}

crypto::ECDSAKey::ECDSAKey(eckey_ptr key)
    : key_(std::move(key)) {
}

const EC_KEY* crypto::ECDSAKey::get() const {
    return key_.get();
}

bool crypto::ECDSAKey::isValid() const {
    return key_ != nullptr;
}

std::optional<crypto::ECDSAKey> crypto::ECDSAKey::generateKeyPair() {
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == nullptr) {
        return std::nullopt;
    }

    eckey_ptr key_ptr(eckey);
    if (!EC_KEY_generate_key(key_ptr.get())) {
        return std::nullopt;
    }

    return ECDSAKey(std::move(key_ptr));
}

std::optional<crypto::ECDSAKey> crypto::ECDSAKey::loadPrivateKeyFromFile(const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (bio == NULL) {
        return std::nullopt;
    }

    EC_KEY* ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
    if (ec_key == NULL) {
        return std::nullopt;
    }

    return ECDSAKey(eckey_ptr(ec_key));
}

std::optional<crypto::ECDSAKey> crypto::ECDSAKey::loadPublicKeyFromFile(const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "r");
    if (bio == NULL) {
        return std::nullopt;
    }

    EC_KEY* ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
    if (ec_key == NULL) {
        return std::nullopt;
    }

    return ECDSAKey(eckey_ptr(ec_key));
}

std::optional<crypto::ECDSAKey> crypto::ECDSAKey::loadPublicKeyFromString(const std::string& public_key) {
    BIO* bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
    if (bio == NULL) {
        return std::nullopt;
    }

    EC_KEY* ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
    if (ec_key == NULL) {
        return std::nullopt;
    }

    return ECDSAKey(eckey_ptr(ec_key));
}

bool crypto::ECDSAKey::savePrivateKey(const std::string& filename) const {
    if (!key_) {
        return false;
    }

    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        return false;
    }

    bool success = PEM_write_bio_ECPrivateKey(bio, key_.get(), nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio);
    return success;
}

bool crypto::ECDSAKey::savePublicKey(const std::string& filename) const {
    if (!key_) {
        return false;
    }

    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        return false;
    }

    bool success = PEM_write_bio_EC_PUBKEY(bio, key_.get());
    BIO_free(bio);
    return success;
}

bool crypto::ECDSAKey::writePublicKeyToBuffer(std::array<uint8_t, EC_PUBLIC_KEY_SIZE_UNCOMPRESSED>& buffer) const {
    if (!key_) return false;

    const EC_POINT* public_point = EC_KEY_get0_public_key(key_.get());
    if (!public_point) {
        return false;
    }

    size_t key_len = EC_POINT_point2oct(
        EC_KEY_get0_group(key_.get()),
        public_point,
        POINT_CONVERSION_UNCOMPRESSED,
        nullptr,
        0,
        nullptr);

    if (key_len != buffer.size()) {
        return false;
    }

    if (EC_POINT_point2oct(EC_KEY_get0_group(key_.get()), public_point, POINT_CONVERSION_UNCOMPRESSED,
        buffer.data(), key_len, NULL) == 0) {
        return false;
    }

    return true;
}

std::optional<crypto::ECDSASignature> crypto::ECDSAKey::signHash(const SHA256Hash& message_hash) const {
    if (!key_) {
        return std::nullopt;
    }

    ECDSA_SIG* signature = ECDSA_do_sign(message_hash.data(), static_cast<int>(message_hash.size()), key_.get());
    if (!signature) {
        return std::nullopt;
    }

    return ECDSASignature(ecdsa_sig_ptr(signature));
}

std::optional<crypto::ECDSASignature> crypto::ECDSAKey::signTransaction(const transaction::serialized_transaction_without_signature& message) const {
    auto hash = SHA256Hash::hash(message);
    if (!hash) {
        return std::nullopt;
    }
    return signHash(*hash);
}

bool crypto::ECDSAKey::verifySignature(const ECDSASignature& signature, const SHA256Hash& message_hash) const {
    if (!key_ || !signature.isValid()) {
        return false;
    }
    return ECDSA_do_verify(message_hash.data(), static_cast<int>(message_hash.size()), signature.get(), key_.get()) == 1;
}
