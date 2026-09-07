#include "twitter_steg.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
#include <span>
#include <stdexcept>
#include <utility>

namespace {

struct PreparedHandle {
    TwitterPreparedCover cover;
};

void setError(
    const char* message,
    char** error_data,
    std::size_t* error_size) noexcept {

    if (error_data == nullptr || error_size == nullptr) return;
    *error_data = nullptr;
    *error_size = 0;
    if (message == nullptr) return;

    const std::size_t size = std::strlen(message);
    if (size == 0) return;
    auto* copy = static_cast<char*>(std::malloc(size));
    if (copy == nullptr) return;
    std::memcpy(copy, message, size);
    *error_data = copy;
    *error_size = size;
}

void clearError(char** error_data, std::size_t* error_size) noexcept {
    if (error_data != nullptr) *error_data = nullptr;
    if (error_size != nullptr) *error_size = 0;
}

void requireInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        throw std::runtime_error(
            "Internal Error: X-Twitter bridge received an invalid input buffer.");
    }
}

void copyBytes(
    std::span<const Byte> input,
    std::uint8_t** output_data,
    std::size_t* output_size) {

    if (output_data == nullptr || output_size == nullptr) {
        throw std::runtime_error(
            "Internal Error: X-Twitter bridge received invalid output pointers.");
    }
    *output_data = nullptr;
    *output_size = 0;
    if (input.empty()) return;

    auto* copy = static_cast<std::uint8_t*>(std::malloc(input.size()));
    if (copy == nullptr) throw std::bad_alloc();
    std::memcpy(copy, input.data(), input.size());
    *output_data = copy;
    *output_size = input.size();
}

template<typename Work>
int ffiCall(
    char** error_data,
    std::size_t* error_size,
    Work&& work) noexcept {

    clearError(error_data, error_size);
    try {
        work();
        return 1;
    } catch (const std::exception& error) {
        setError(error.what(), error_data, error_size);
    } catch (...) {
        setError("Unknown X-Twitter carrier error.", error_data, error_size);
    }
    return -1;
}

} // namespace

extern "C" int jdvrif_twitter_inspect(
    const std::uint8_t* input_data,
    std::size_t input_size,
    std::uint32_t* width,
    std::uint32_t* height,
    char** error_data,
    std::size_t* error_size) noexcept {

    return ffiCall(error_data, error_size, [&] {
        requireInput(input_data, input_size);
        if (width == nullptr || height == nullptr) {
            throw std::runtime_error(
                "Internal Error: X-Twitter bridge received invalid inspection pointers.");
        }
        const TwitterCoverDimensions dimensions = inspectTwitterCover(
            std::span<const Byte>(input_data, input_size));
        *width = dimensions.width;
        *height = dimensions.height;
    });
}

extern "C" int jdvrif_twitter_prepare(
    const std::uint8_t* input_data,
    std::size_t input_size,
    void** prepared_handle,
    std::uint32_t* width,
    std::uint32_t* height,
    int* source_quality,
    int* carrier_quality,
    std::size_t* payload_capacity,
    std::size_t* prepared_jpeg_size,
    char** error_data,
    std::size_t* error_size) noexcept {

    if (prepared_handle != nullptr) *prepared_handle = nullptr;
    return ffiCall(error_data, error_size, [&] {
        requireInput(input_data, input_size);
        if (prepared_handle == nullptr || width == nullptr || height == nullptr ||
            source_quality == nullptr || carrier_quality == nullptr ||
            payload_capacity == nullptr || prepared_jpeg_size == nullptr) {
            throw std::runtime_error(
                "Internal Error: X-Twitter bridge received invalid preparation pointers.");
        }

        TwitterPreparedCover cover = prepareTwitterCover(
            std::span<const Byte>(input_data, input_size));
        auto* handle = new PreparedHandle{std::move(cover)};
        *width = handle->cover.width;
        *height = handle->cover.height;
        *source_quality = handle->cover.source_quality;
        *carrier_quality = handle->cover.carrier_quality;
        *payload_capacity = handle->cover.payload_capacity;
        *prepared_jpeg_size = handle->cover.jpeg.size();
        *prepared_handle = handle;
    });
}

extern "C" void jdvrif_twitter_prepared_free(void* prepared_handle) noexcept {
    delete static_cast<PreparedHandle*>(prepared_handle);
}

extern "C" int jdvrif_twitter_embed(
    const void* prepared_handle,
    std::uint64_t carrier_key,
    const std::uint8_t* payload_data,
    std::size_t payload_size,
    std::uint8_t** output_data,
    std::size_t* output_size,
    char** error_data,
    std::size_t* error_size) noexcept {

    if (output_data != nullptr) *output_data = nullptr;
    if (output_size != nullptr) *output_size = 0;
    return ffiCall(error_data, error_size, [&] {
        requireInput(payload_data, payload_size);
        if (prepared_handle == nullptr) {
            throw std::runtime_error(
                "Internal Error: X-Twitter bridge received an invalid prepared cover.");
        }
        const auto& handle = *static_cast<const PreparedHandle*>(prepared_handle);
        const vBytes embedded = embedTwitterPayload(
            handle.cover,
            carrier_key,
            std::span<const Byte>(payload_data, payload_size));
        copyBytes(embedded, output_data, output_size);
    });
}

extern "C" int jdvrif_twitter_extract(
    const std::uint8_t* input_data,
    std::size_t input_size,
    std::uint64_t carrier_key,
    std::uint8_t** kdf_data,
    std::size_t* kdf_size,
    std::uint8_t** encrypted_data,
    std::size_t* encrypted_size,
    int* is_compressed,
    char** error_data,
    std::size_t* error_size) noexcept {

    if (kdf_data != nullptr) *kdf_data = nullptr;
    if (kdf_size != nullptr) *kdf_size = 0;
    if (encrypted_data != nullptr) *encrypted_data = nullptr;
    if (encrypted_size != nullptr) *encrypted_size = 0;
    if (is_compressed != nullptr) *is_compressed = 0;
    clearError(error_data, error_size);

    try {
        requireInput(input_data, input_size);
        if (kdf_data == nullptr || kdf_size == nullptr || encrypted_data == nullptr ||
            encrypted_size == nullptr || is_compressed == nullptr) {
            throw std::runtime_error(
                "Internal Error: X-Twitter bridge received invalid extraction pointers.");
        }

        const auto envelope = extractTwitterEnvelope(
            std::span<const Byte>(input_data, input_size),
            carrier_key);
        if (!envelope) return 0;

        copyBytes(envelope->kdf_metadata, kdf_data, kdf_size);
        try {
            copyBytes(envelope->encrypted_data, encrypted_data, encrypted_size);
        } catch (...) {
            std::free(*kdf_data);
            *kdf_data = nullptr;
            *kdf_size = 0;
            throw;
        }
        *is_compressed = envelope->is_compressed ? 1 : 0;
        return 1;
    } catch (const std::exception& error) {
        setError(error.what(), error_data, error_size);
    } catch (...) {
        setError("Unknown X-Twitter carrier error.", error_data, error_size);
    }
    return -1;
}

extern "C" void jdvrif_twitter_buffer_free(void* buffer) noexcept {
    std::free(buffer);
}
