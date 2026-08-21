package io.ubin;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Arrays;

public final class ProtocolSelfTest {
    public static void main(String[] args) {
        byte[] payload = "hello UBIN".getBytes(StandardCharsets.UTF_8);
        byte[] envelope = UbinWire.encodeEnvelope(payload, 1, 0);
        String hex = HexFormat.of().formatHex(envelope);
        if (!hex.equals("55424e32020100000000000a68656c6c6f205542494e")) throw new AssertionError(hex);
        UbinWire.Envelope decoded = UbinWire.decodeEnvelope(envelope);
        if (!Arrays.equals(payload, decoded.payload())) throw new AssertionError("payload mismatch");
        System.out.println("PASS: Java UBIN v2-draft envelope vector");
    }
}
