package de.dogcraft.ssltest.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

public class URLParsing {

    public static class TestParameter {

        String proto;

        String host;

        int port;

        public TestParameter(String proto, String domain, int port) {
            this.proto = proto;
            this.host = domain;
            this.port = port;
        }

        public String getProtocol() {
            return proto;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

    }

    public static class TestParameterParsingException extends Exception {

        public TestParameterParsingException(String message) {
            super(message);
        }

        private static final long serialVersionUID = 1L;

    }

    public static TestParameter parse(HttpServletRequest req) throws TestParameterParsingException {
        TestParameter u1 = generateURL(req);
        TestParameter u2 = guessURL(u1.getHost());
        if (u2 != null) {
            u1 = u2;
        }
        return u1;
    }

    private static TestParameter generateURL(HttpServletRequest req) throws TestParameterParsingException {
        String domain = req.getParameter("domain");
        if (null == domain) {
            throw new TestParameterParsingException("error params missing");
        }
        String proto = "direct";
        int port;
        String portStr = req.getParameter("port");
        if (portStr == null || portStr.trim().equals("")) {
            port = 443;
        } else {
            if (portStr.indexOf('-') != -1) {
                proto = portStr.split("-", 2)[0];
                portStr = portStr.split("-", 2)[1];
            }
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException nfe) {
                throw new TestParameterParsingException("port is not an Integer");
            }

        }

        return new TestParameter(proto, domain, port);
    }

    private static final Pattern p = Pattern.compile("([a-zA-Z]+)://([^:/]+)(?::([0-9]+))?(?:/.*)?");

    private static TestParameter guessURL(String domain) throws TestParameterParsingException {
        Matcher m = p.matcher(domain);
        if ( !m.matches()) {
            return null;
        }
        String proto = null;
        switch (m.group(1)) {
        case "https":
        case "direct":
        case "ssl":
        case "tls":
            proto = "direct";
            break;
        case "smtp":
        case "smtps":
            proto = "smtp";
            break;
        case "imap":
        case "imaps":
            proto = "imap";
            break;
        case "xmpp":
        case "xmpps":
            proto = "xmpp";
            break;
        case "xmpp-server":
        case "xmpps-server":
            proto = "xmpp-server";
            break;

        }
        int port = -1;
        if (m.group(3) != null) {
            port = Integer.parseInt(m.group(3));
        }
        if (port == -1) {
            switch (m.group(1)) {
            case "https":
                port = 443;
                break;
            case "smtp":
            case "smtps":
                port = 25;
                break;
            case "imap":
            case "imaps":
                port = 143;
                break;
            case "pop":
            case "pops":
                port = 110;
                break;
            }
        }
        if (port == -1) {
            throw new TestParameterParsingException("port could not be determined out of URL");
        }
        if (proto == null) {
            throw new TestParameterParsingException("protocol could not be determined out of URL");
        }
        return new TestParameter(proto, m.group(2), port);
    }

}
