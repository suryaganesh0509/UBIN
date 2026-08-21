package io.ubin;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** UBIN 2 stable wire-format reference implementation for Java. */
public final class UbinWire {
    public static final int VERSION = 2;
    public static final int HEADER_SIZE = 12;
    public static final int MESSAGE_TYPE_VALUE = 1;
    public static final int DEFAULT_MAX_PAYLOAD = 64 * 1024 * 1024;
    public static final int DEFAULT_MAX_ITEMS = 1_000_000;
    public static final int MAX_DEPTH = 64;

    private UbinWire() {}

    public record Envelope(int version, int messageType, int flags, byte[] payload) {}

    public static byte[] encodeEnvelope(byte[] payload, int messageType, int flags) {
        if (payload == null) throw new NullPointerException("payload");
        if (messageType < 0 || messageType > 255) throw new IllegalArgumentException("messageType");
        if (flags < 0 || flags > 65535) throw new IllegalArgumentException("flags");
        ByteBuffer out = ByteBuffer.allocate(HEADER_SIZE + payload.length).order(ByteOrder.BIG_ENDIAN);
        out.put(new byte[] {'U', 'B', 'N', '2'});
        out.put((byte) VERSION);
        out.put((byte) messageType);
        out.putShort((short) flags);
        out.putInt(payload.length);
        out.put(payload);
        return out.array();
    }

    public static Envelope decodeEnvelope(byte[] data) {
        return decodeEnvelope(data, DEFAULT_MAX_PAYLOAD);
    }

    public static Envelope decodeEnvelope(byte[] data, int maxPayload) {
        if (data == null) throw new NullPointerException("data");
        if (maxPayload < 0) throw new IllegalArgumentException("maxPayload");
        if (data.length < HEADER_SIZE || data[0] != 'U' || data[1] != 'B' || data[2] != 'N' || data[3] != '2')
            throw new IllegalArgumentException("invalid UBIN envelope");
        ByteBuffer in = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        in.position(4);
        int version = Byte.toUnsignedInt(in.get());
        if (version != VERSION) throw new IllegalArgumentException("unsupported UBIN protocol version");
        int messageType = Byte.toUnsignedInt(in.get());
        int flags = Short.toUnsignedInt(in.getShort());
        long length = Integer.toUnsignedLong(in.getInt());
        if (length > maxPayload || length > Integer.MAX_VALUE || data.length != HEADER_SIZE + (int) length)
            throw new IllegalArgumentException("UBIN envelope length mismatch or limit exceeded");
        return new Envelope(version, messageType, flags, Arrays.copyOfRange(data, HEADER_SIZE, data.length));
    }

    public static byte[] encodeValue(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encodeValueInto(value, out, 0);
        return out.toByteArray();
    }

    private static void encodeValueInto(Object value, ByteArrayOutputStream out, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("UBIN value nesting is too deep");
        if (value == null) { out.write(0x00); return; }
        if (value instanceof Boolean b) { out.write(b ? 0x02 : 0x01); return; }
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
            out.write(0x10);
            writeLong(out, ((Number) value).longValue());
            return;
        }
        if (value instanceof Float || value instanceof Double) {
            double d = ((Number) value).doubleValue();
            if (!Double.isFinite(d)) throw new IllegalArgumentException("UBIN canonical float must be finite");
            out.write(0x11);
            writeLong(out, Double.doubleToRawLongBits(d));
            return;
        }
        if (value instanceof byte[] bytes) {
            out.write(0x20); writeU32(out, bytes.length); out.writeBytes(bytes); return;
        }
        if (value instanceof String text) {
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            out.write(0x21); writeU32(out, bytes.length); out.writeBytes(bytes); return;
        }
        if (value instanceof List<?> list) {
            out.write(0x30); writeU32(out, list.size());
            for (Object item : list) encodeValueInto(item, out, depth + 1);
            return;
        }
        if (value instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object key : map.keySet()) {
                if (!(key instanceof String s)) throw new IllegalArgumentException("UBIN canonical map keys must be strings");
                keys.add(s);
            }
            keys.sort(Comparator.comparing(s -> s.getBytes(StandardCharsets.UTF_8), UbinWire::compareUnsigned));
            out.write(0x31); writeU32(out, keys.size());
            for (String key : keys) {
                encodeValueInto(key, out, depth + 1);
                encodeValueInto(map.get(key), out, depth + 1);
            }
            return;
        }
        throw new IllegalArgumentException("unsupported UBIN canonical value type: " + value.getClass().getName());
    }

    public static Object decodeValue(byte[] data) {
        if (data == null) throw new NullPointerException("data");
        if (data.length > DEFAULT_MAX_PAYLOAD) throw new IllegalArgumentException("UBIN value exceeds byte limit");
        Reader reader = new Reader(data, DEFAULT_MAX_ITEMS);
        Object value = reader.value(0);
        if (reader.offset != data.length) throw new IllegalArgumentException("trailing bytes after UBIN value");
        return value;
    }

    public static byte[] encodeMessage(Object value) {
        return encodeEnvelope(encodeValue(value), MESSAGE_TYPE_VALUE, 0);
    }

    public static Object decodeMessage(byte[] data) {
        Envelope envelope = decodeEnvelope(data);
        if (envelope.messageType() != MESSAGE_TYPE_VALUE)
            throw new IllegalArgumentException("UBIN envelope is not a canonical-value message");
        return decodeValue(envelope.payload());
    }

    private static final class Reader {
        private final byte[] data;
        private final int maxItems;
        private int offset;
        private int items;

        Reader(byte[] data, int maxItems) { this.data = data; this.maxItems = maxItems; }

        private byte[] take(int size) {
            if (size < 0 || offset > data.length - size) throw new IllegalArgumentException("truncated UBIN value");
            byte[] result = Arrays.copyOfRange(data, offset, offset + size);
            offset += size;
            return result;
        }

        private long u32() {
            byte[] b = take(4);
            return ((long)(b[0] & 0xff) << 24) | ((long)(b[1] & 0xff) << 16) | ((long)(b[2] & 0xff) << 8) | (b[3] & 0xffL);
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) throw new IllegalArgumentException("UBIN value nesting is too deep");
            if (++items > maxItems) throw new IllegalArgumentException("UBIN value item limit exceeded");
            int tag = take(1)[0] & 0xff;
            return switch (tag) {
                case 0x00 -> null;
                case 0x01 -> false;
                case 0x02 -> true;
                case 0x10 -> ByteBuffer.wrap(take(8)).order(ByteOrder.BIG_ENDIAN).getLong();
                case 0x11 -> {
                    double d = ByteBuffer.wrap(take(8)).order(ByteOrder.BIG_ENDIAN).getDouble();
                    if (!Double.isFinite(d)) throw new IllegalArgumentException("non-finite UBIN float");
                    yield d;
                }
                case 0x20 -> {
                    long length = u32();
                    if (length > Integer.MAX_VALUE) throw new IllegalArgumentException("UBIN byte string too large");
                    yield take((int) length);
                }
                case 0x21 -> {
                    long length = u32();
                    if (length > Integer.MAX_VALUE) throw new IllegalArgumentException("UBIN string too large");
                    byte[] raw = take((int) length);
                    try {
                        yield StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(raw)).toString();
                    } catch (CharacterCodingException e) {
                        throw new IllegalArgumentException("invalid UBIN UTF-8 string", e);
                    }
                }
                case 0x30 -> {
                    long count = u32();
                    if (count > maxItems - items) throw new IllegalArgumentException("UBIN value item limit exceeded");
                    List<Object> list = new ArrayList<>((int)Math.min(count, 4096));
                    for (long i = 0; i < count; i++) list.add(value(depth + 1));
                    yield list;
                }
                case 0x31 -> {
                    long count = u32();
                    if (count > (maxItems - items) / 2L) throw new IllegalArgumentException("UBIN value item limit exceeded");
                    Map<String, Object> map = new LinkedHashMap<>();
                    byte[] previous = null;
                    for (long i = 0; i < count; i++) {
                        Object keyObject = value(depth + 1);
                        if (!(keyObject instanceof String key)) throw new IllegalArgumentException("UBIN map key is not a string");
                        byte[] encoded = key.getBytes(StandardCharsets.UTF_8);
                        if (previous != null && compareUnsigned(encoded, previous) <= 0)
                            throw new IllegalArgumentException("UBIN map keys are not in canonical order");
                        previous = encoded;
                        map.put(key, value(depth + 1));
                    }
                    yield map;
                }
                default -> throw new IllegalArgumentException(String.format("unknown UBIN value tag: 0x%02x", tag));
            };
        }
    }

    private static void writeU32(ByteArrayOutputStream out, long value) {
        if (value < 0 || value > 0xffff_ffffL) throw new IllegalArgumentException("UBIN u32 overflow");
        out.write((int)(value >>> 24)); out.write((int)(value >>> 16)); out.write((int)(value >>> 8)); out.write((int)value);
    }

    private static void writeLong(ByteArrayOutputStream out, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) out.write((int)(value >>> shift));
    }

    private static int compareUnsigned(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int cmp = Integer.compare(a[i] & 0xff, b[i] & 0xff);
            if (cmp != 0) return cmp;
        }
        return Integer.compare(a.length, b.length);
    }
}
