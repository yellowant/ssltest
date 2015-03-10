package de.dogcraft.ssltest.utils;

public class JSONUtils {

    public static String jsonEscape(String s) {
        if (s == null) {
            return ""; // TODO Maybe actual JSON-Null values?
        }

        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace("\b", "\\b").replace("\f", "\\f");
    }

}
