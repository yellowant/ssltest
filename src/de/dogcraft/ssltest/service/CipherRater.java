package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletResponse;

public class CipherRater {

    private static final String unknown = "#dddddd";

    private static final String none = "#ff4444";

    private static final String[] names = new String[] {
            "40less", "40", "64", "80", "96", "112", "128", "160", "192", "224", "256"
    };

    private static final String[] colors = new String[] {
            "#ff6666", "#ff8888", "#ffaaaa", "#ffcccc", "#ffdddd", "#ffeedd", "#ffffdd", "#f7ffdd", "#eeffdd", "#e6ffdd", "#ddffdd"
    };

    public static void generateRateCSS(HttpServletResponse resp) throws IOException {
        resp.setContentType("text/css");
        generateSymmeq(resp.getWriter());
    }

    public static void generateSymmeq(PrintWriter out) {
        outputSymmeqRule(out, unknown, "unknown");
        outputSymmeqRule(out, none, "none");
        for (int i = 0; i < names.length; i++) {
            outputSymmeqRule(out, colors[i], names[i]);
        }
    }

    private static void outputSymmeqRule(PrintWriter out, String color, String name) {
        out.println("table.ciphertable, td.symmeq-" + name + " {");
        out.println("\tbackground-color: " + color);
        out.println("}");
        out.println(".cert-trust.symmeq-" + name + " {");
        out.println("\tfill: " + color);
        out.println("}");
    }

}
