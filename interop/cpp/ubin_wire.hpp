#ifndef UBIN_WIRE_HPP
#define UBIN_WIRE_HPP

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace ubin {

constexpr std::uint8_t protocol_version = 2;
constexpr std::size_t header_size = 12;
constexpr std::uint8_t message_type_value = 1;

struct envelope {
    std::uint8_t version;
    std::uint8_t message_type;
    std::uint16_t flags;
    std::vector<std::uint8_t> payload;
};

inline std::vector<std::uint8_t> encode_envelope(const std::vector<std::uint8_t>& payload,
                                                  std::uint8_t message_type = message_type_value,
                                                  std::uint16_t flags = 0) {
    if (payload.size() > 0xffffffffULL) throw std::length_error("UBIN payload too large");
    const auto size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> out;
    out.reserve(header_size + payload.size());
    out.insert(out.end(), {'U', 'B', 'N', '2', protocol_version, message_type});
    out.push_back(static_cast<std::uint8_t>(flags >> 8)); out.push_back(static_cast<std::uint8_t>(flags));
    out.push_back(static_cast<std::uint8_t>(size >> 24)); out.push_back(static_cast<std::uint8_t>(size >> 16));
    out.push_back(static_cast<std::uint8_t>(size >> 8)); out.push_back(static_cast<std::uint8_t>(size));
    out.insert(out.end(), payload.begin(), payload.end()); return out;
}

inline envelope decode_envelope(const std::vector<std::uint8_t>& data, std::size_t max_payload = 64ULL * 1024 * 1024) {
    if (data.size() < header_size || data[0] != 'U' || data[1] != 'B' || data[2] != 'N' || data[3] != '2')
        throw std::invalid_argument("invalid UBIN envelope");
    if (data[4] != protocol_version) throw std::invalid_argument("unsupported UBIN protocol version");
    std::uint32_t size = (static_cast<std::uint32_t>(data[8]) << 24) | (static_cast<std::uint32_t>(data[9]) << 16) |
                         (static_cast<std::uint32_t>(data[10]) << 8) | static_cast<std::uint32_t>(data[11]);
    if (size > max_payload || data.size() != header_size + static_cast<std::size_t>(size))
        throw std::invalid_argument("UBIN envelope length mismatch or limit exceeded");
    return {data[4], data[5], static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[6]) << 8) | data[7]),
            std::vector<std::uint8_t>(data.begin() + static_cast<std::ptrdiff_t>(header_size), data.end())};
}

class writer {
public:
    std::vector<std::uint8_t> data;
    writer& null_value() { data.push_back(0x00); return *this; }
    writer& boolean(bool value) { data.push_back(value ? 0x02 : 0x01); return *this; }
    writer& int64(std::int64_t value) { data.push_back(0x10); put_u64(static_cast<std::uint64_t>(value)); return *this; }
    writer& float64(double value) {
        if (!std::isfinite(value)) throw std::invalid_argument("UBIN canonical float must be finite");
        std::uint64_t bits; std::memcpy(&bits, &value, sizeof bits); data.push_back(0x11); put_u64(bits); return *this;
    }
    writer& bytes(const std::vector<std::uint8_t>& value) {
        if (value.size() > 0xffffffffULL) throw std::length_error("UBIN bytes too large");
        data.push_back(0x20); put_u32(static_cast<std::uint32_t>(value.size())); data.insert(data.end(), value.begin(), value.end()); return *this;
    }
    writer& string(const std::string& value) {
        if (value.size() > 0xffffffffULL) throw std::length_error("UBIN string too large");
        data.push_back(0x21); put_u32(static_cast<std::uint32_t>(value.size())); data.insert(data.end(), value.begin(), value.end()); return *this;
    }
    writer& list_header(std::uint32_t count) { data.push_back(0x30); put_u32(count); return *this; }
    writer& map_header(std::uint32_t count) { data.push_back(0x31); put_u32(count); return *this; }
private:
    void put_u32(std::uint32_t v) { data.push_back(v>>24); data.push_back(v>>16); data.push_back(v>>8); data.push_back(v); }
    void put_u64(std::uint64_t v) { for (int shift=56; shift>=0; shift-=8) data.push_back(static_cast<std::uint8_t>(v>>shift)); }
};

} // namespace ubin
#endif
