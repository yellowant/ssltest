package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class STARTTLS {

    public static Socket starttls(Socket s, String proto) {

        try {
            if (proto.equals("smtp")){
                startSMTP(s);
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

}
