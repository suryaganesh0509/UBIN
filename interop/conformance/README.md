# Stable Conformance Vectors

`vectors.json` is generated from the UBIN 2 Python reference implementation and is treated as immutable compatibility data for the 2.x protocol line.

Every language implementation must reproduce `canonical_value_hex` and `envelope_hex` exactly. `canonical_message_hex` is the canonical value wrapped as message type 1.

Changing an existing vector is a protocol-breaking change and is not permitted in a 2.x release.
