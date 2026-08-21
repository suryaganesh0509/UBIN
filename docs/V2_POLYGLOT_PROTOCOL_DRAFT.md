# UBIN 2 Polyglot Protocol — Draft

**Status:** draft carried by v1.0.7; not frozen ABI/wire compatibility.

## Why

Programming languages do not need to understand each other's source syntax. They need a shared representation. UBIN defines canonical bytes plus framing so Python, C, C++, Java, and later languages can exchange the same logical values and resources.

## Canonical value tags

| Tag | Type | Representation |
|---|---|---|
| `00` | null | no payload |
| `01` | false | no payload |
| `02` | true | no payload |
| `10` | int64 | signed big-endian 8 bytes |
| `11` | float64 | finite IEEE-754 big-endian 8 bytes |
| `20` | bytes | u32 length + raw bytes |
| `21` | UTF-8 string | u32 length + UTF-8 |
| `30` | list | u32 count + canonical values |
| `31` | map | u32 count + UTF-8 string keys in bytewise canonical order + values |

Integers outside signed 64-bit are rejected in this draft. NaN and infinities are rejected so encodings stay deterministic. Map keys must be strings and are sorted by encoded UTF-8 bytes. All multibyte integers use network byte order (big-endian).

## Envelope

`UBN2 | version:u8 | message_type:u8 | flags:u16be | payload_length:u32be | payload`

Magic is ASCII `UBN2`, draft protocol version is `2`. This envelope is deliberately small and is **not itself encryption**. The v2 secure profile will bind framing and canonical metadata to authenticated transport/container primitives.

## Stable v2 gate

Before v2.0, the final protocol must pass pairwise interoperability across Python, C, C++, and Java, including valid vectors, malformed/truncated inputs, size limits, canonical maps, Unicode, streams, errors, and security vectors.
