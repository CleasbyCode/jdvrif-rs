#pragma once

#include <sodium.h>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using Byte = std::uint8_t;
using vBytes = std::vector<Byte>;

[[noreturn]] inline void throwError(std::string_view message) {
    throw std::runtime_error(std::string(message));
}

inline void throwIf(bool condition, std::string_view message) {
    if (condition) throwError(message);
}

struct CoverImageLimits {
    std::uint32_t max_dimension;
    std::uint64_t max_pixels;
};

inline constexpr CoverImageLimits DEFAULT_COVER_IMAGE_LIMITS{
    4'096,
    4'096ULL * 4'096ULL,
};
inline constexpr CoverImageLimits REDDIT_COVER_IMAGE_LIMITS{
    8'192,
    8'192ULL * 8'192ULL,
};

// Same constraint and byte-count rule as the C++ reference (src/common.h):
// only contiguous containers of trivially copyable, non-pointer elements, and
// the wipe covers capacity() * sizeof(element) bytes.
template<typename Container>
concept WipeableContainer =
    std::ranges::contiguous_range<Container> &&
    std::is_trivially_copyable_v<std::ranges::range_value_t<Container>> &&
    !std::is_pointer_v<std::ranges::range_value_t<Container>> &&
    requires(Container& c, std::size_t n) {
        { c.capacity() } -> std::convertible_to<std::size_t>;
        c.resize(n);
        c.clear();
        c.shrink_to_fit();
    };

template<WipeableContainer Container>
inline void wipeContainerCapacity(Container& container) noexcept {
    constexpr std::size_t element_size = sizeof(std::ranges::range_value_t<Container>);
    if (const std::size_t cap = container.capacity(); cap > 0) {
        try {
            container.resize(cap);
        } catch (...) {
            if (!container.empty()) sodium_memzero(container.data(), container.size() * element_size);
            return;
        }
        sodium_memzero(container.data(), cap * element_size);
    }
    container.clear();
    try {
        container.shrink_to_fit();
    } catch (...) {
    }
}

template<WipeableContainer Container>
struct WipeContainerGuard {
    Container* container{nullptr};

    explicit WipeContainerGuard(Container& c) noexcept : container(&c) {}
    WipeContainerGuard(const WipeContainerGuard&) = delete;
    WipeContainerGuard& operator=(const WipeContainerGuard&) = delete;

    ~WipeContainerGuard() {
        if (container) wipeContainerCapacity(*container);
    }
};

using WipeBytesGuard = WipeContainerGuard<vBytes>;
