#pragma once

#include <sodium.h>

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

struct CoverImageLimits {
    std::uint32_t max_dimension;
    std::uint64_t max_pixels;
};

inline constexpr CoverImageLimits DEFAULT_COVER_IMAGE_LIMITS{
    16'384,
    40'000'000,
};
inline constexpr CoverImageLimits REDDIT_COVER_IMAGE_LIMITS{
    8'192,
    8'192ULL * 8'192ULL,
};

template<typename Container>
inline void wipeContainerCapacity(Container& container) noexcept {
    if (const std::size_t cap = container.capacity(); cap > 0) {
        try {
            container.resize(cap);
        } catch (...) {
            if (!container.empty()) sodium_memzero(container.data(), container.size());
            return;
        }
        sodium_memzero(container.data(), cap);
    }
    container.clear();
    try {
        container.shrink_to_fit();
    } catch (...) {
    }
}

template<typename Container>
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
