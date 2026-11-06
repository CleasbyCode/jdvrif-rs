#pragma once

#include "common.h"

#include <limits>
#include <span>
#include <stdexcept>

[[nodiscard]] constexpr bool spanHasRange(
    std::span<const Byte> data,
    std::size_t index,
    std::size_t length) {
    return index <= data.size() && length <= data.size() - index;
}

[[nodiscard]] inline std::size_t checkedAdd(
    std::size_t a,
    std::size_t b,
    const char* error_message) {
    if (a > std::numeric_limits<std::size_t>::max() - b) {
        throw std::overflow_error(error_message);
    }
    return a + b;
}
