#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <array>

#include "utilities/timestamps.h"

// Get current UTC timestamp as ISO 8601 string
std::string utilities::get_current_utc_timestamp_str() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t now_time_t = system_clock::to_time_t(now);

    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &now_time_t);  // Windows-safe
#else
    gmtime_r(&now_time_t, &utc_tm);  // POSIX-safe
#endif

    std::ostringstream oss;
    oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");  // ISO 8601 UTC
    return oss.str();
}

// Cross-platform alternative to timegm
time_t utilities::timegm_crossplatform(std::tm* tm) {
#if defined(_WIN32)
    // Windows _mkgmtime converts struct tm as UTC -> time_t
    return _mkgmtime(tm);
#else
    // On POSIX, we can emulate timegm by adjusting mktime to UTC
    return timegm(tm);  // Most Linux systems have this
#endif
}

// Parse ISO 8601 timestamp string back into time_point
std::chrono::system_clock::time_point utilities::parse_utc_timestamp_str(const std::string& timestamp_str) {
    std::tm tm{};
    std::istringstream ss(timestamp_str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (ss.fail()) {
        throw std::runtime_error("Failed to parse timestamp string");
    }

    std::time_t time = utilities::timegm_crossplatform(&tm);
    return std::chrono::system_clock::from_time_t(time);
}


// Store time_point into 8-byte buffer (milliseconds since epoch, little-endian)
void utilities::write_timestamp_to_buffer(std::chrono::system_clock::time_point tp, std::array<unsigned char, SERIALIZED_TIMESTAMP_SIZE>& buffer) {
    using namespace std::chrono;
    int64_t millis = duration_cast<milliseconds>(tp.time_since_epoch()).count();

    for (int i = 0; i < 8; ++i) {
        buffer[i] = static_cast<uint8_t>((millis >> (i * 8)) & 0xFF);
    }
}

// Reconstruct time_point from 8-byte buffer (little-endian)
std::chrono::system_clock::time_point utilities::read_timestamp_from_buffer(std::array<unsigned char, SERIALIZED_TIMESTAMP_SIZE>& buffer) {
    int64_t millis = 0;
    for (int i = 0; i < 8; ++i) {
        millis |= static_cast<int64_t>(buffer[i]) << (i * 8);
    }

    return std::chrono::system_clock::time_point{std::chrono::milliseconds{millis}};
}