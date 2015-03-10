package de.dogcraft.ssltest.utils;

public class JSONUtils {

    public static String jsonEscape(String s) {

        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace("\b", "\\b").replace("\f", "\\f");
    }

}
