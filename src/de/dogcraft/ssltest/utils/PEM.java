package de.dogcraft.ssltest.utils;

import java.util.Base64;
import java.util.regex.Pattern;

public class PEM {

    public static final Pattern LINE = Pattern.compile("(.{64})(?=.)");

    public static String encode(String type, byte[] data) {
        return "-----BEGIN " + type + "-----\n" + //
                formatBase64(data) + //
                "\n-----END " + type + "-----";
    }

    public static byte[] decode(String type, String data) {
        // Remove the first and last lines
        data = data.replaceAll("-----BEGIN " + type + "-----", "");
        data = data.replaceAll("-----END " + type + "-----", "");

        // Remove whitespace
        data = data.replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "");

        // Base64 decode the data
        return Base64.getDecoder().decode(data);

    }

    public static String formatBase64(byte[] bytes) {
        return LINE.matcher(Base64.getEncoder().encodeToString(bytes)).replaceAll("$1\n");
    }

}
