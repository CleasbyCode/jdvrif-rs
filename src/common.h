#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Byte = std::uint8_t;
using vBytes = std::vector<Byte>;

[[noreturn]] inline void throwError(std::string_view message) {
    throw std::runtime_error(std::string(message));
}

inline void throwIf(bool condition, std::string_view message) {
    if (condition) throwError(message);
}
