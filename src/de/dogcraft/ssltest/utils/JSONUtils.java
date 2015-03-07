package de.dogcraft.ssltest.utils;

public class JSONUtils {

    public static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
