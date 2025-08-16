// sidcoin.cpp : Defines the entry point for the application.
//

#include <vector>
#include <fstream>
#include <iomanip>

#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>

#include "sidcoin.h"
#include "transaction/transaction.h"
#include "block/block.h"
#include "crypto/sha256.h"
#include "crypto/ecdsa.h"


using namespace std;

int main() {
    std::string message = "Hello, world!";
    //int ret = 0;
    //std::vector<unsigned char> hash = crypto::sha256(message, ret);

    //std::cout << "SHA256 Hash: ";
    //for (unsigned char byte : hash) {
    //    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    //}
    //std::cout << std::endl;

    //EC_KEY* new_key = crypto::generate_ecdsa_key_pair();
    //if (new_key == NULL) {
    //    return EXIT_FAILURE;
    //}

    //ECDSA_SIG* signature = crypto::sign_message(message, new_key);

    //std::cout << "R: " << crypto::ecdsa_signature_r_as_hex_string(signature) << std::endl;
    //std::cout << "S: " << crypto::ecdsa_signature_s_as_hex_string(signature) << std::endl;

    //int signature_isvalid = crypto::verify_signature(message, signature, new_key);
    //std::cout << "Signature valid: " << signature_isvalid << std::endl;

    //crypto::save_ec_private_key(new_key, "SIDCOIN_ecdsa_secp256k1_private_key.pem");
    //crypto::save_ec_public_key(new_key, "SIDCOIN_ecdsa_secp256k1_public_key.pem");
    //
    //crypto::free_ec_key(new_key);
    //

    //new_key = crypto::generate_ecdsa_key_pair();
    //ret = crypto::load_ecdsa_private_key_from_file(crypto::DEFAULT_PRIVATE_KEY_FILE, new_key);
    //if (ret != 0) {
    //    std::cout << "Failed to load private key" << std::endl;
    //}

    //ret = crypto::load_ecdsa_public_key_from_file(crypto::DEFAULT_PUBLIC_KEY_FILE, new_key);
    //if (ret != 0) {
    //    std::cout << "Failed to load public key" << std::endl;
    //}
    //
    //ret = EC_KEY_check_key(new_key);
    //if (ret != 1) {
    //    std::cout << "Problem with key" << std::endl;
    //}

    //signature_isvalid = crypto::verify_signature(message, signature, new_key);
    //std::cout << "Signature valid: " << signature_isvalid << std::endl;
    //
    ////signature = crypto::sign_message(message, new_key);
    //std::string r = crypto::ecdsa_signature_r_as_hex_string(signature);
    //std::string s = crypto::ecdsa_signature_s_as_hex_string(signature);
    //
    //if (r.size() == 0 || s.size() == 0) {
    //    std::cout << "Problem generating string from signature" << std::endl;;
    //    ECDSA_SIG_free(signature);
    //    crypto::free_ec_key(new_key);
    //    return -1;
    //}

    //ECDSA_SIG_free(signature);
    //
    //signature = crypto::ecdsa_signature_from_hex_strings(r, s);
    //if (signature == NULL) {
    //    std::cout << "Problem reconstructing signature from strings" << std::endl;
    //    ECDSA_SIG_free(signature);
    //    crypto::free_ec_key(new_key);
    //    return -1;
    //}
    //signature_isvalid = crypto::verify_signature(message, signature, new_key);
    //std::cout << "Signature valid: " << signature_isvalid << std::endl;

    //crypto::free_ec_key(new_key);
    //ECDSA_SIG_free(signature);

    std::ifstream test_tx("assets/test_tx.json");
    if (!test_tx.is_open()) {
        return -1;
    }

    std::ifstream test_bk("assets/test_block.json");
    if (!test_bk.is_open()) {
        test_tx.close();
        return -1;
    }

    nlohmann::json test_tx_json;
    try {
        test_tx_json = nlohmann::json::parse(test_tx);
    }
    catch (nlohmann::json::exception e) {
        std::cout << e.what();
        return -1;
    }

    nlohmann::json test_bk_json;
    try {
        test_bk_json = nlohmann::json::parse(test_bk);
    }
    catch (nlohmann::json::exception e) {
        std::cout << e.what();
        return -1;
    }


    try {
        transaction::Transaction tx = transaction::Transaction(test_tx_json);
        block::Block bk = block::Block(test_bk_json);

        transaction::serialized_transaction_with_signature* serialized_tx = transaction::serialize_transaction_with_signature(tx);
        block::serialized_block* serialized_bk = block::serialize_block(bk);

        delete serialized_tx;
        delete serialized_bk;
    }
    catch (std::exception e) {
        std::cout << e.what();
    }

    test_bk.close();
    test_tx.close();
    return 0;

}