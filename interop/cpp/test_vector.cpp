#include "ubin_wire.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

static std::string hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out; for (auto byte : bytes) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte); return out.str();
}

int main() {
    const std::string text = "hello UBIN"; std::vector<std::uint8_t> payload(text.begin(), text.end());
    const auto bytes = ubin::encode_envelope(payload);
    if (hex(bytes) != "55424e32020100000000000a68656c6c6f205542494e") return 1;
    if (ubin::decode_envelope(bytes).payload != payload) return 2;

    ubin::writer w;
    w.map_header(4).string("bytes").bytes({0,1}).string("language").string("UBIN").string("ok").boolean(true).string("version").int64(2);
    if (hex(w.data) != "3100000004210000000562797465732000000002000121000000086c616e677561676521000000045542494e21000000026f6b02210000000776657273696f6e100000000000000002") return 3;
    std::cout << "PASS: C++ UBIN v2 stable envelope + canonical-value vectors\n"; return 0;
}
