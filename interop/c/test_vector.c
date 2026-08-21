#include "ubin_wire.h"
#include <stdio.h>
#include <string.h>

static const char *EXPECTED_ENVELOPE = "55424e32020100000000000a68656c6c6f205542494e";
static const char *EXPECTED_VALUE = "3100000004210000000562797465732000000002000121000000086c616e677561676521000000045542494e21000000026f6b02210000000776657273696f6e100000000000000002";
static void to_hex(const uint8_t *data, size_t length, char *out) { static const char H[] = "0123456789abcdef"; size_t i; for (i=0;i<length;++i){out[i*2]=H[data[i]>>4];out[i*2+1]=H[data[i]&15];} out[length*2]='\0'; }

int main(void) {
    const uint8_t payload[] = "hello UBIN"; uint8_t encoded[256]; char hex[513]; ubin_wire_envelope decoded;
    size_t size = ubin_wire_encode_envelope(payload, 10u, 1u, 0u, encoded, sizeof encoded);
    if (!size) return 1;
    to_hex(encoded, size, hex);
    if (strcmp(hex, EXPECTED_ENVELOPE)) return 2;
    if (!ubin_wire_decode_envelope(encoded, size, &decoded) || decoded.payload_length != 10u || memcmp(decoded.payload,payload,10u)) return 3;

    ubin_writer w; const uint8_t bytes[] = {0,1}; ubin_writer_init(&w, encoded, sizeof encoded);
    /* Canonical map order: bytes, language, ok, version. */
    if (!ubin_write_map_header(&w,4u) || !ubin_write_string(&w,"bytes",5u) || !ubin_write_bytes(&w,bytes,2u) ||
        !ubin_write_string(&w,"language",8u) || !ubin_write_string(&w,"UBIN",4u) || !ubin_write_string(&w,"ok",2u) ||
        !ubin_write_bool(&w,1) || !ubin_write_string(&w,"version",7u) || !ubin_write_int64(&w,2)) return 4;
    to_hex(encoded, w.length, hex); if (strcmp(hex, EXPECTED_VALUE)) return 5;
    puts("PASS: C UBIN v2 stable envelope + canonical-value vectors"); return 0;
}
