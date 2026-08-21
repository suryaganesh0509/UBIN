#include "ubin_wire.h"

#include <math.h>
#include <string.h>

static void put_u16_be(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8); out[1] = (uint8_t)value;
}
static void put_u32_be(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16); out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}
static uint16_t get_u16_be(const uint8_t *data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}
static uint32_t get_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

size_t ubin_wire_encode_envelope(const uint8_t *payload, uint32_t payload_length, uint8_t message_type,
                                 uint16_t flags, uint8_t *out, size_t out_capacity) {
    size_t total = UBIN_WIRE_HEADER_SIZE + (size_t)payload_length;
    if (out == NULL || (payload_length != 0u && payload == NULL) || out_capacity < total) return 0u;
    out[0] = 'U'; out[1] = 'B'; out[2] = 'N'; out[3] = '2'; out[4] = UBIN_WIRE_VERSION; out[5] = message_type;
    put_u16_be(out + 6, flags); put_u32_be(out + 8, payload_length);
    if (payload_length != 0u) memcpy(out + UBIN_WIRE_HEADER_SIZE, payload, payload_length);
    return total;
}

int ubin_wire_decode_envelope(const uint8_t *data, size_t data_length, ubin_wire_envelope *out) {
    uint32_t payload_length;
    if (data == NULL || out == NULL || data_length < UBIN_WIRE_HEADER_SIZE) return 0;
    if (data[0] != 'U' || data[1] != 'B' || data[2] != 'N' || data[3] != '2' || data[4] != UBIN_WIRE_VERSION) return 0;
    payload_length = get_u32_be(data + 8);
    if (data_length != UBIN_WIRE_HEADER_SIZE + (size_t)payload_length) return 0;
    out->version = data[4]; out->message_type = data[5]; out->flags = get_u16_be(data + 6);
    out->payload_length = payload_length; out->payload = data + UBIN_WIRE_HEADER_SIZE;
    return 1;
}

void ubin_writer_init(ubin_writer *w, uint8_t *data, size_t capacity) {
    if (w == NULL) {
        return;
    }
    w->data = data;
    w->capacity = capacity;
    w->length = 0u;
    w->ok = data != NULL;
}
static int write_raw(ubin_writer *w, const uint8_t *data, size_t size) {
    if (w == NULL || !w->ok || size > w->capacity - w->length) { if (w != NULL) w->ok = 0; return 0; }
    if (size != 0u) {
        memcpy(w->data + w->length, data, size);
    }
    w->length += size;
    return 1;
}
static int write_tag(ubin_writer *w, uint8_t tag) { return write_raw(w, &tag, 1u); }
static int write_u32(ubin_writer *w, uint32_t value) { uint8_t b[4]; put_u32_be(b, value); return write_raw(w, b, 4u); }
int ubin_write_null(ubin_writer *w) { return write_tag(w, UBIN_TAG_NULL); }
int ubin_write_bool(ubin_writer *w, int value) { return write_tag(w, value ? UBIN_TAG_TRUE : UBIN_TAG_FALSE); }
int ubin_write_int64(ubin_writer *w, int64_t value) {
    uint8_t b[9]; uint64_t u = (uint64_t)value; int i; b[0] = UBIN_TAG_INT64;
    for (i = 0; i < 8; ++i) {
        b[1 + i] = (uint8_t)(u >> (56 - i * 8));
    }
    return write_raw(w, b, 9u);
}
int ubin_write_float64(ubin_writer *w, double value) {
    uint64_t bits; uint8_t b[9]; int i; if (!isfinite(value)) return 0; memcpy(&bits, &value, sizeof bits); b[0] = UBIN_TAG_FLOAT64;
    for (i = 0; i < 8; ++i) {
        b[1 + i] = (uint8_t)(bits >> (56 - i * 8));
    }
    return write_raw(w, b, 9u);
}
int ubin_write_bytes(ubin_writer *w, const uint8_t *data, uint32_t length) {
    return write_tag(w, UBIN_TAG_BYTES) && write_u32(w, length) && (length == 0u || write_raw(w, data, length));
}
int ubin_write_string(ubin_writer *w, const char *utf8, uint32_t length) {
    return write_tag(w, UBIN_TAG_STRING) && write_u32(w, length) && (length == 0u || write_raw(w, (const uint8_t *)utf8, length));
}
int ubin_write_list_header(ubin_writer *w, uint32_t count) { return write_tag(w, UBIN_TAG_LIST) && write_u32(w, count); }
int ubin_write_map_header(ubin_writer *w, uint32_t count) { return write_tag(w, UBIN_TAG_MAP) && write_u32(w, count); }

void ubin_reader_init(ubin_reader *r, const uint8_t *data, size_t length) {
    if (r == NULL) {
        return;
    }
    r->data = data;
    r->length = length;
    r->offset = 0u;
    r->ok = data != NULL || length == 0u;
}
static int read_raw(ubin_reader *r, size_t size, const uint8_t **out) {
    if (r == NULL || !r->ok || size > r->length - r->offset) { if (r != NULL) r->ok = 0; return 0; }
    if (out != NULL) {
        *out = r->data + r->offset;
    }
    r->offset += size;
    return 1;
}
int ubin_read_tag(ubin_reader *r, uint8_t *tag) { const uint8_t *p; if (!read_raw(r, 1u, &p)) return 0; if (tag != NULL) *tag = p[0]; return 1; }
int ubin_read_u32(ubin_reader *r, uint32_t *value) { const uint8_t *p; if (!read_raw(r, 4u, &p)) return 0; if (value != NULL) *value = get_u32_be(p); return 1; }
int ubin_read_int64(ubin_reader *r, int64_t *value) {
    const uint8_t *p; uint64_t u = 0u; int i; if (!read_raw(r, 8u, &p)) return 0; for (i = 0; i < 8; ++i) u = (u << 8) | p[i]; if (value != NULL) *value = (int64_t)u; return 1;
}
int ubin_read_float64(ubin_reader *r, double *value) {
    const uint8_t *p; uint64_t bits = 0u; double d; int i; if (!read_raw(r, 8u, &p)) return 0; for (i = 0; i < 8; ++i) bits = (bits << 8) | p[i]; memcpy(&d, &bits, sizeof d); if (!isfinite(d)) return 0; if (value != NULL) *value = d; return 1;
}
int ubin_read_span(ubin_reader *r, uint32_t length, const uint8_t **data) { return read_raw(r, length, data); }
