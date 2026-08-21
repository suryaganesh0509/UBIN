package io.ubin;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public final class UbinWire {
    private UbinWire() {}

    public record Envelope(int version, int messageType, int flags, byte[] payload) {}

    public static byte[] encodeEnvelope(byte[] payload, int messageType, int flags) {
        if (messageType < 0 || messageType > 255) throw new IllegalArgumentException("messageType");
        if (flags < 0 || flags > 65535) throw new IllegalArgumentException("flags");
        ByteBuffer out = ByteBuffer.allocate(12 + payload.length).order(ByteOrder.BIG_ENDIAN);
        out.put(new byte[] {'U', 'B', 'N', '2'});
        out.put((byte)2);
        out.put((byte)messageType);
        out.putShort((short)flags);
        out.putInt(payload.length);
        out.put(payload);
        return out.array();
    }

    public static Envelope decodeEnvelope(byte[] data) {
        if (data.length < 12 || data[0] != 'U' || data[1] != 'B' || data[2] != 'N' || data[3] != '2')
            throw new IllegalArgumentException("invalid UBIN envelope");
        ByteBuffer in = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        in.position(4);
        int version = Byte.toUnsignedInt(in.get());
        if (version != 2) throw new IllegalArgumentException("unsupported UBIN protocol version");
        int messageType = Byte.toUnsignedInt(in.get());
        int flags = Short.toUnsignedInt(in.getShort());
        int length = in.getInt();
        if (length < 0 || data.length != 12 + length) throw new IllegalArgumentException("UBIN envelope length mismatch");
        return new Envelope(version, messageType, flags, Arrays.copyOfRange(data, 12, data.length));
    }
}
