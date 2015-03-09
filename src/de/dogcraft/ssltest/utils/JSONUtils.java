package de.dogcraft.ssltest.utils;

public class JSONUtils {

    public static String jsonEscape(String s) {

        return s.replaceAll("\\\\", "\\\\\\\\").replaceAll("\"", "\\\"").replaceAll("\\n", "\\\\n").replaceAll("\\r", "\\\\r").replaceAll("\\t", "\\\\t").replaceAll("\\b", "\\\\b").replaceAll("\\f", "\\\\f");

    }

}
