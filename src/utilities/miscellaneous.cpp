#include <vector>
#include <string>
#include <cstdint>

#include "utilities/miscellaneous.h"

std::vector<uint8_t> utilities::hex_string_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2); // Reserve space for efficiency

    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}