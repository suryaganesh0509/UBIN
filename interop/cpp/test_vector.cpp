#include "ubin_wire.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

int main() {
    const std::string text = "hello UBIN";
    std::vector<std::uint8_t> payload(text.begin(), text.end());
    const auto bytes = ubin::encode_envelope(payload);
    std::ostringstream out;
    for (auto byte : bytes) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    if (out.str() != "55424e32020100000000000a68656c6c6f205542494e") return 1;
    const auto decoded = ubin::decode_envelope(bytes);
    if (decoded.payload != payload) return 2;
    std::cout << "PASS: C++ UBIN v2-draft envelope vector\n";
    return 0;
}
