package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class STARTTLS {

    public static Socket starttls(Socket s, String proto, String domain) {

        try {
            if (proto.equals("smtp")) {
                startSMTP(s);
            }
            if (proto.equals("xmpp")) {
                System.out.println("xmpp-ing");
                startXMPP(s, false, domain);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return s;

    }

    private static void startSMTP(Socket s) throws IOException {
        InputStream is = s.getInputStream();
        readSMTP(is);
        s.getOutputStream().write("EHLO ssl.pinger\r\n".getBytes());
        s.getOutputStream().flush();
        readSMTP(is);
        s.getOutputStream().write("HELP\r\n".getBytes());
        s.getOutputStream().flush();
        readSMTP(is);
        s.getOutputStream().write("STARTTLS\r\n".getBytes());
        s.getOutputStream().flush();
        readSMTP(is);
    }

    private static void readSMTP(InputStream is) throws IOException {
        int counter = 0;
        boolean finish = true;
        while (true) {
            char c = (char) is.read();
            if (counter == 3) {
                if (c == ' ') {
                    finish = true;
                } else if (c == '-') {
                    finish = false;
                } else {
                    throw new Error("Invalid smtp: " + c);
                }
            }
            if (c == '\n') {
                if (finish) {
                    return;
                }
                counter = 0;
            } else {
                counter++;
            }
        }
    }

    private static void scanFor(InputStream is, String scanFor) throws IOException {
        int pos = 0;
        while (pos < scanFor.length()) {
            if (is.read() == scanFor.charAt(pos)) {
                pos++;
            } else {
                pos = 0;
            }
        }
    }

    private static void startXMPP(Socket s, boolean server, String domain) throws IOException {
        InputStream is = s.getInputStream();
        OutputStream os = s.getOutputStream();
        os.write(("<stream:stream to=\"" + domain + "\" xmlns=\"jabber:" + (server ? "server" : "client") + "\"" + " xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">").getBytes());
        os.flush();
        os.write("<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>".getBytes());
        os.flush();
        scanFor(is, "<proceed");
        scanFor(is, ">");

    }

}
