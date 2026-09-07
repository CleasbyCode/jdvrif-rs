/* Regenerate the JPEGs used by twitter.rs without adding production FFI hooks.
From the crate root:
g++ -std=c++20 -O2 -Isrc src/testdata/generate_twitter_capacity_fixtures.cpp \
    src/twitter_steg.cpp src/twitter_jpeg_codec.cpp src/twitter_juniward.cpp \
    src/twitter_stc.cpp -ljpeg -lsodium -o /tmp/twitter-capacity-fixtures
/tmp/twitter-capacity-fixtures src/testdata
*/
#include "twitter_steg.h"
#include "twitter_juniward.h"
#include "twitter_stc.h"

#include <jpeglib.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>

// Standalone fixture generation does not install the Rust signal handlers.
void throwIfSignalCancellationRequested() {}
int pendingSignalCancellation() noexcept { return 0; }

namespace {

[[nodiscard]] vBytes makeSmallCover() {
    jpeg_compress_struct encoder{};
    jpeg_error_mgr errors{};
    encoder.err = jpeg_std_error(&errors);
    jpeg_create_compress(&encoder);
    unsigned char* output = nullptr;
    unsigned long output_size = 0;
    jpeg_mem_dest(&encoder, &output, &output_size);
    encoder.image_width = 400;
    encoder.image_height = 400;
    encoder.input_components = 3;
    encoder.in_color_space = JCS_RGB;
    jpeg_set_defaults(&encoder);
    jpeg_set_quality(&encoder, 90, TRUE);
    jpeg_start_compress(&encoder, TRUE);
    std::array<JSAMPLE, 400 * 3> row;
    row.fill(128);
    while (encoder.next_scanline < encoder.image_height) {
        JSAMPROW scanline = row.data();
        jpeg_write_scanlines(&encoder, &scanline, 1);
    }
    jpeg_finish_compress(&encoder);
    jpeg_destroy_compress(&encoder);
    const std::unique_ptr<unsigned char, decltype(&std::free)> guard(
        output, &std::free);
    return vBytes(output, output + output_size);
}

[[nodiscard]] std::uint64_t mix64(std::uint64_t value) {
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

[[nodiscard]] std::uint32_t crc32(std::span<const Byte> bytes) {
    std::uint32_t crc = 0xffffffffU;
    for (const Byte byte : bytes) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1U) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

// Embed a valid checksum and keyed header directly: the normal embedding API
// correctly refuses lengths exceeding the cover's advertised capacity.
[[nodiscard]] vBytes makeOversizedHeader(
    const TwitterPreparedCover& cover,
    std::uint64_t carrier_key,
    std::uint32_t declared_size) {

    using namespace twitter_steg_internal;
    auto coefficients = cover.coefficients;
    const auto layout = makeCarrierLayout(
        coefficients, mix64(carrier_key ^ 0x4a58535445474c31ULL));
    std::array<Byte, 24> header{
        'J', 'X', 'S', 'T', 'E', 'G', '2', 0, 2, 7, 2, 5};
    for (unsigned int byte = 0; byte < 4; ++byte) {
        header[12 + byte] = static_cast<Byte>(declared_size >> (byte * 8U));
    }
    const auto checksum = crc32(std::span<const Byte>(header).first(20));
    for (unsigned int byte = 0; byte < 4; ++byte) {
        header[20 + byte] = static_cast<Byte>(checksum >> (byte * 8U));
    }
    vBytes header_bits(header.size() * 8U);
    for (std::size_t bit = 0; bit < header_bits.size(); ++bit) {
        const auto stream = mix64(
            carrier_key ^ 0x4a58535445474831ULL ^ (bit / 64U));
        header_bits[bit] = static_cast<Byte>(
            ((header[bit / 8U] >> (bit % 8U)) ^
             (stream >> (bit % 64U))) & 1U);
    }
    const auto offsets = std::span<const std::uint32_t>(layout.coefficient_offsets)
        .first(static_cast<std::size_t>(requiredCoverSymbols(header_bits.size())));
    const auto parity = coefficientParityBits(coefficients.luminance, offsets);
    const auto embedded = stcEmbed(
        parity, std::vector<float>(offsets.size(), 1), header_bits);
    (void)applyParityBits(coefficients.luminance, offsets, embedded.stego_bits, 0);
    return writeProgressiveCoefficients(cover.jpeg, coefficients.luminance);
}

void writeFixture(const std::filesystem::path& path, std::span<const Byte> bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("failed to write JPEG fixture");
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) return 2;
        using namespace twitter_steg_internal;
        const std::filesystem::path output_dir(argv[1]);
        const auto base = makeSmallCover();
        auto coefficients = readCoefficients(base);
        for (std::size_t offset = 0; offset < coefficients.luminance.size(); ++offset) {
            if (offset % 64U != 0) coefficients.luminance[offset] = 1;
        }
        const auto cover = prepareTwitterCover(
            writeProgressiveCoefficients(base, coefficients.luminance));
        if (cover.payload_capacity != 7851) {
            throw std::runtime_error("unexpected low-amplitude fixture capacity");
        }
        writeFixture(output_dir / "twitter_low_amplitude.jpg", cover.jpeg);
        writeFixture(output_dir / "twitter_oversized_header.jpg",
            makeOversizedHeader(cover, 42,
                static_cast<std::uint32_t>(cover.payload_capacity + 1U)));
        writeFixture(output_dir / "twitter_maximum_header.jpg",
            makeOversizedHeader(cover, 42,
                std::numeric_limits<std::uint32_t>::max()));
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
