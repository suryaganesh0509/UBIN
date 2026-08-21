#include "ubin_wire.h"
#include <stdio.h>
#include <string.h>

static const char *EXPECTED = "55424e32020100000000000a68656c6c6f205542494e";

static void to_hex(const uint8_t *data, size_t length, char *out) {
    static const char HEX[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < length; ++i) {
        out[i * 2] = HEX[data[i] >> 4];
        out[i * 2 + 1] = HEX[data[i] & 0x0f];
    }
    out[length * 2] = '\0';
}

int main(void) {
    const uint8_t payload[] = "hello UBIN";
    uint8_t encoded[64];
    char hex[129];
    ubin_wire_envelope decoded;
    size_t size = ubin_wire_encode_envelope(payload, 10u, 1u, 0u, encoded, sizeof encoded);
    if (size == 0u) return 1;
    to_hex(encoded, size, hex);
    if (strcmp(hex, EXPECTED) != 0) return 2;
    if (!ubin_wire_decode_envelope(encoded, size, &decoded)) return 3;
    if (decoded.payload_length != 10u || memcmp(decoded.payload, payload, 10u) != 0) return 4;
    puts("PASS: C UBIN v2-draft envelope vector");
    return 0;
}
