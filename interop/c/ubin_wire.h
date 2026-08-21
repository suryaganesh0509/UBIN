#ifndef UBIN_WIRE_H
#define UBIN_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define UBIN_WIRE_HEADER_SIZE 12u
#define UBIN_WIRE_VERSION 2u
#define UBIN_MESSAGE_TYPE_VALUE 1u

#define UBIN_TAG_NULL   0x00u
#define UBIN_TAG_FALSE  0x01u
#define UBIN_TAG_TRUE   0x02u
#define UBIN_TAG_INT64  0x10u
#define UBIN_TAG_FLOAT64 0x11u
#define UBIN_TAG_BYTES  0x20u
#define UBIN_TAG_STRING 0x21u
#define UBIN_TAG_LIST   0x30u
#define UBIN_TAG_MAP    0x31u

typedef struct ubin_wire_envelope {
    uint8_t version;
    uint8_t message_type;
    uint16_t flags;
    uint32_t payload_length;
    const uint8_t *payload;
} ubin_wire_envelope;

typedef struct ubin_writer {
    uint8_t *data;
    size_t capacity;
    size_t length;
    int ok;
} ubin_writer;

typedef struct ubin_reader {
    const uint8_t *data;
    size_t length;
    size_t offset;
    int ok;
} ubin_reader;

size_t ubin_wire_encode_envelope(const uint8_t *payload, uint32_t payload_length, uint8_t message_type,
                                 uint16_t flags, uint8_t *out, size_t out_capacity);
int ubin_wire_decode_envelope(const uint8_t *data, size_t data_length, ubin_wire_envelope *out);

void ubin_writer_init(ubin_writer *writer, uint8_t *data, size_t capacity);
int ubin_write_null(ubin_writer *writer);
int ubin_write_bool(ubin_writer *writer, int value);
int ubin_write_int64(ubin_writer *writer, int64_t value);
int ubin_write_float64(ubin_writer *writer, double value);
int ubin_write_bytes(ubin_writer *writer, const uint8_t *data, uint32_t length);
int ubin_write_string(ubin_writer *writer, const char *utf8, uint32_t length);
int ubin_write_list_header(ubin_writer *writer, uint32_t count);
int ubin_write_map_header(ubin_writer *writer, uint32_t count);

void ubin_reader_init(ubin_reader *reader, const uint8_t *data, size_t length);
int ubin_read_tag(ubin_reader *reader, uint8_t *tag);
int ubin_read_u32(ubin_reader *reader, uint32_t *value);
int ubin_read_int64(ubin_reader *reader, int64_t *value);
int ubin_read_float64(ubin_reader *reader, double *value);
int ubin_read_span(ubin_reader *reader, uint32_t length, const uint8_t **data);

#endif
