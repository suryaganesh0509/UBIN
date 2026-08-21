package io.ubin;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ProtocolSelfTest {
    private static final String ENVELOPE = "55424e32020100000000000a68656c6c6f205542494e";
    private static final String VALUE = "3100000004210000000562797465732000000002000121000000086c616e677561676521000000045542494e21000000026f6b02210000000776657273696f6e100000000000000002";

    public static void main(String[] args) {
        byte[] payload = "hello UBIN".getBytes(StandardCharsets.UTF_8);
        byte[] envelope = UbinWire.encodeEnvelope(payload, 1, 0);
        if (!HexFormat.of().formatHex(envelope).equals(ENVELOPE)) throw new AssertionError("envelope vector");
        UbinWire.Envelope decoded = UbinWire.decodeEnvelope(envelope);
        if (!Arrays.equals(payload, decoded.payload())) throw new AssertionError("payload mismatch");

        Map<String, Object> value = new LinkedHashMap<>();
        value.put("version", 2L);
        value.put("language", "UBIN");
        value.put("ok", true);
        value.put("bytes", new byte[] {0, 1});
        byte[] canonical = UbinWire.encodeValue(value);
        if (!HexFormat.of().formatHex(canonical).equals(VALUE)) throw new AssertionError("canonical vector");
        Object roundTrip = UbinWire.decodeValue(canonical);
        if (!(roundTrip instanceof Map<?, ?> map) || !Boolean.TRUE.equals(map.get("ok"))) throw new AssertionError("canonical decode");

        System.out.println("PASS: Java UBIN v2 stable envelope + canonical-value vectors");
    }
}
