#ifndef UBIN_WIRE_H
#define UBIN_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define UBIN_WIRE_HEADER_SIZE 12u
#define UBIN_WIRE_VERSION 2u

typedef struct ubin_wire_envelope {
    uint8_t version;
    uint8_t message_type;
    uint16_t flags;
    uint32_t payload_length;
    const uint8_t *payload;
} ubin_wire_envelope;

size_t ubin_wire_encode_envelope(
    const uint8_t *payload,
    uint32_t payload_length,
    uint8_t message_type,
    uint16_t flags,
    uint8_t *out,
    size_t out_capacity
);

int ubin_wire_decode_envelope(
    const uint8_t *data,
    size_t data_length,
    ubin_wire_envelope *out
);

#endif
