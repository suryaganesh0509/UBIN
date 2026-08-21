#include "ubin_wire.h"

static void put_u16_be(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put_u32_be(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint16_t get_u16_be(const uint8_t *data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t get_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

size_t ubin_wire_encode_envelope(
    const uint8_t *payload,
    uint32_t payload_length,
    uint8_t message_type,
    uint16_t flags,
    uint8_t *out,
    size_t out_capacity
) {
    size_t total = UBIN_WIRE_HEADER_SIZE + (size_t)payload_length;
    uint32_t i;
    if (out == NULL || (payload_length != 0u && payload == NULL) || out_capacity < total) {
        return 0u;
    }
    out[0] = 'U'; out[1] = 'B'; out[2] = 'N'; out[3] = '2';
    out[4] = UBIN_WIRE_VERSION;
    out[5] = message_type;
    put_u16_be(out + 6, flags);
    put_u32_be(out + 8, payload_length);
    for (i = 0u; i < payload_length; ++i) {
        out[UBIN_WIRE_HEADER_SIZE + i] = payload[i];
    }
    return total;
}

int ubin_wire_decode_envelope(
    const uint8_t *data,
    size_t data_length,
    ubin_wire_envelope *out
) {
    uint32_t payload_length;
    if (data == NULL || out == NULL || data_length < UBIN_WIRE_HEADER_SIZE) {
        return 0;
    }
    if (data[0] != 'U' || data[1] != 'B' || data[2] != 'N' || data[3] != '2') {
        return 0;
    }
    if (data[4] != UBIN_WIRE_VERSION) {
        return 0;
    }
    payload_length = get_u32_be(data + 8);
    if (data_length != UBIN_WIRE_HEADER_SIZE + (size_t)payload_length) {
        return 0;
    }
    out->version = data[4];
    out->message_type = data[5];
    out->flags = get_u16_be(data + 6);
    out->payload_length = payload_length;
    out->payload = data + UBIN_WIRE_HEADER_SIZE;
    return 1;
}
