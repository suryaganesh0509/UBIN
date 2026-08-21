# UBIN Protocol 2 — Stable Polyglot Wire Specification

**Status:** Stable and frozen for UBIN 2.x  
**Protocol version:** `2`  
**Magic:** ASCII `UBN2`  
**Reference release:** UBIN `2.0.0`

UBIN Protocol 2 is a language-neutral byte contract. Programming languages do not exchange source syntax or runtime objects directly; they encode a small shared set of logical values into canonical bytes and place those bytes in a fixed envelope. Python, C, C++, Java, or any other language can interoperate by producing and accepting these bytes exactly.

Normative words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe compatibility requirements.

## 1. Design goals

- deterministic bytes for the same supported logical value;
- trivial framing that can be implemented without UBIN's Python package;
- bounded parsing of untrusted data;
- no dependence on machine endianness, pointer width, object layout, locale, or source-language syntax;
- stable test vectors shared by all implementations;
- forward extensibility through message types and flags without silently reinterpreting v2 bytes.

## 2. Byte order

Every multi-byte integer and IEEE-754 payload is **big-endian/network byte order**.

## 3. Canonical values

| Tag | Logical type | Payload |
|---:|---|---|
| `0x00` | null | none |
| `0x01` | false | none |
| `0x02` | true | none |
| `0x10` | signed integer | exactly 8-byte two's-complement int64 |
| `0x11` | float | exactly 8-byte finite IEEE-754 binary64 |
| `0x20` | bytes | u32 byte length + raw bytes |
| `0x21` | string | u32 byte length + valid UTF-8 bytes |
| `0x30` | list | u32 item count + canonical value for each item |
| `0x31` | map | u32 pair count + canonical string key/value pairs |

### Integer rules

Integers MUST fit `[-2^63, 2^63-1]`. Encoders MUST reject larger values instead of truncating them.

### Float rules

NaN and positive/negative infinity MUST be rejected. Finite binary64 values, including signed zero, are represented by their IEEE-754 bit pattern.

### String rules

Strings MUST be valid UTF-8. Length is the number of encoded UTF-8 bytes, not characters, code points, or UTF-16 units. UBIN does not perform Unicode normalization; normalization is application policy.

### Map rules

Map keys MUST be strings. Encoders MUST sort keys by unsigned lexicographic comparison of their UTF-8 byte sequences. Decoders MUST reject duplicate or non-increasing keys. This makes map bytes deterministic independent of source-language map iteration order.

### Nesting and resource limits

The reference implementation limits nesting depth to 64 and defaults to 1,000,000 decoded items and 64 MiB for protocol payload/value bytes. Implementations MAY expose lower policy limits, but MUST reject over-limit inputs safely rather than partially decoding them.

## 4. Envelope

The envelope is exactly:

```text
0               4 5 6   8          12
+---------------+-+-+---+-----------+------------------+
| "UBN2"        |V|T| F | Length    | Payload          |
+---------------+-+-+---+-----------+------------------+
   4 bytes       1 1  2     4        Length bytes
```

Fields:

- magic: 4 bytes, exactly `55 42 4e 32` (`UBN2`);
- version: u8, exactly `2` for this protocol;
- message type: u8;
- flags: u16 big-endian;
- payload length: u32 big-endian;
- payload: exactly the declared number of bytes.

A decoder MUST reject invalid magic, an unsupported version, truncation, trailing bytes, and payloads above its configured limit.

## 5. Stable message types

- `1` — canonical UBIN value (`encode_value` payload)
- `2` — uninterpreted application bytes

Types `3..255` are unassigned in 2.0.0. Implementations MUST NOT invent conflicting meanings in the core protocol. Application-specific use should be negotiated outside the core or registered in a future protocol revision.

Flags are currently application/profile-defined. A component that assigns flag semantics MUST document them; the core framing layer only preserves the 16-bit field.

## 6. Conformance vectors

The authoritative machine-readable vectors are in `interop/conformance/vectors.json`. A conforming implementation MUST reproduce the stable envelope and canonical-value vectors byte-for-byte and reject the malformed cases defined by its conformance suite.

The baseline logical map is:

```text
{
  "bytes": 00 01,
  "language": "UBIN",
  "ok": true,
  "version": 2
}
```

Canonical key order is `bytes`, `language`, `ok`, `version`.

## 7. Language mappings

| UBIN type | Python | C reference | C++ reference | Java |
|---|---|---|---|---|
| null | `None` | tag helper | writer helper | `null` |
| bool | `bool` | `ubin_write_bool` | `writer.boolean` | `Boolean` |
| int64 | `int` in range | `int64_t` | `std::int64_t` | integral wrappers decoded as `Long` |
| float64 | `float` | `double` | `double` | `Double` |
| bytes | `bytes` | span | `vector<uint8_t>` | `byte[]` |
| string | `str` | UTF-8 span | UTF-8 `std::string` | `String` |
| list | list/tuple | count + recursive values | count + recursive values | `List<?>` |
| map | `dict[str, ...]` | count + sorted pairs | count + sorted pairs | `Map<String, ?>` |

The C and C++ reference layers intentionally expose low-level writer/reader primitives so callers can map the protocol onto their own allocation strategy instead of forcing a particular object model.

## 8. Security properties and non-properties

Protocol 2 provides canonical serialization and framing. It is **not encryption, authentication, authorization, or trust establishment**. Sensitive traffic must be protected by an authenticated UBIN secure profile or another appropriate authenticated transport. Never treat successful protocol decoding as proof that the sender is trusted.

Parsers must treat lengths, counts, tags, UTF-8, and nesting as untrusted input. They must fail closed on malformed data.

## 9. Compatibility policy

Protocol bytes defined in this document are frozen for the UBIN 2 major line. A UBIN 2.x implementation MUST NOT change the meaning or byte representation of existing tags or envelope fields. New behavior must be additive and must preserve existing conformance vectors.

A future incompatible wire change requires a new protocol version/magic contract and explicit migration documentation.

## 10. Other languages

UBIN does not need a bespoke runtime package for every programming language. A language becomes wire-compatible by implementing this specification and passing the shared vectors. This keeps UBIN universal without making interoperability dependent on Python, a foreign-function interface, or a specific build system.
