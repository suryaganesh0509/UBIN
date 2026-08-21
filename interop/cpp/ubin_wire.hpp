#ifndef UBIN_WIRE_HPP
#define UBIN_WIRE_HPP

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace ubin {

struct envelope {
    std::uint8_t version;
    std::uint8_t message_type;
    std::uint16_t flags;
    std::vector<std::uint8_t> payload;
};

inline std::vector<std::uint8_t> encode_envelope(
    const std::vector<std::uint8_t>& payload,
    std::uint8_t message_type = 1,
    std::uint16_t flags = 0
) {
    if (payload.size() > 0xffffffffULL) throw std::length_error("UBIN payload too large");
    const auto size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> out;
    out.reserve(12 + payload.size());
    out.insert(out.end(), {'U', 'B', 'N', '2', 2, message_type});
    out.push_back(static_cast<std::uint8_t>(flags >> 8));
    out.push_back(static_cast<std::uint8_t>(flags));
    out.push_back(static_cast<std::uint8_t>(size >> 24));
    out.push_back(static_cast<std::uint8_t>(size >> 16));
    out.push_back(static_cast<std::uint8_t>(size >> 8));
    out.push_back(static_cast<std::uint8_t>(size));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

inline envelope decode_envelope(const std::vector<std::uint8_t>& data) {
    if (data.size() < 12 || data[0] != 'U' || data[1] != 'B' || data[2] != 'N' || data[3] != '2')
        throw std::invalid_argument("invalid UBIN envelope");
    if (data[4] != 2) throw std::invalid_argument("unsupported UBIN protocol version");
    std::uint32_t size = (static_cast<std::uint32_t>(data[8]) << 24) |
                         (static_cast<std::uint32_t>(data[9]) << 16) |
                         (static_cast<std::uint32_t>(data[10]) << 8) |
                         static_cast<std::uint32_t>(data[11]);
    if (data.size() != 12ULL + size) throw std::invalid_argument("UBIN envelope length mismatch");
    envelope value{
        data[4], data[5],
        static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[6]) << 8) | data[7]),
        std::vector<std::uint8_t>(data.begin() + 12, data.end())
    };
    return value;
}

} // namespace ubin
#endif
