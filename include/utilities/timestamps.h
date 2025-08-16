#ifndef TIMESTAMPS_H
#define TIMESTAMPS_H

#include <chrono>
#include <format>
#include <iostream>
#include <sstream>
#include <string>

#include "sidcoin_constants.h"

namespace utilities {
	

	// Cross-platform alternative to timegm
	time_t timegm_crossplatform(std::tm* tm);

	// Get a ISO 9601 timestamp string for right now
	std::string get_current_utc_timestamp_str();

	// Parse ISO 8601 timestamp string back into time_point
	std::chrono::system_clock::time_point parse_utc_timestamp_str(const std::string& timestamp_str);

    // Store time_point into 8-byte buffer (milliseconds since epoch, little-endian)
    void write_timestamp_to_buffer(std::chrono::system_clock::time_point tp, std::array<unsigned char, SERIALIZED_TIMESTAMP_SIZE>& buffer);

    // Reconstruct time_point from 8-byte buffer (little-endian)
	std::chrono::system_clock::time_point read_timestamp_from_buffer(std::array<unsigned char, SERIALIZED_TIMESTAMP_SIZE>& buffer);

}
#endif