package de.dogcraft.ssltest;

import java.io.IOException;
import java.net.Socket;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.ExtensionType;

import de.dogcraft.ssltest.output.PrintstreamTestOutput;
import de.dogcraft.ssltest.tests.TestCipherList;
import de.dogcraft.ssltest.tests.TestConnectionBuilder;
import de.dogcraft.ssltest.tests.TestImplementationBugs;
import de.dogcraft.ssltest.tests.TestOutput;

public class CommandLine {

    public static void main(String[] args) throws IOException {
        if (0 == args.length || args.length > 2) {
            System.out.println("Usage: java -jar ssltest.jar " + CommandLine.class.getName() + " host [port]");
            System.out.println();
            System.out.println("    host            The host you want to check");
            System.out.println("    port            The port of the SSL/TLS-based service you want to check");
            System.out.println();
            System.out.println("Testing might take some time ...");
            System.exit(1);
        }

        final String host = args[0];

        final int port;
        if (args.length < 2) {
            port = 443;
        } else {
            port = Integer.parseInt(args[1], 10);
        }

        TestOutput to = new PrintstreamTestOutput(System.out);
        TestConnectionBuilder tcb = new TestConnectionBuilder() {

            @Override
            public Socket spawn() throws IOException {
                return new Socket(host, port);
            }
        };
        TestImplementationBugs bugs = new TestImplementationBugs(host, tcb);

        TestCipherList cipherlist = new TestCipherList(host, tcb);
        String[] ciph = cipherlist.determineCiphers(to);
        for (String string : ciph) {
            System.out.println(string);
        }
        if (cipherlist.hasServerPref()) {
            System.out.println("Server prefers.");
        } else {
            System.out.println("Server doesn't care.");
        }
        Certificate[] c = bugs.getCert().getCertificateList();
        for (Certificate c1 : c) {
            System.out.println("i: " + c1.getIssuer().toString());
            System.out.println(c1.getSubject().toString());
        }

        byte[] sn = (byte[]) bugs.getExt().get(ExtensionType.server_name);
        byte[] hb = (byte[]) bugs.getExt().get(ExtensionType.heartbeat);
        byte[] rn = (byte[]) bugs.getExt().get(ExtensionType.renegotiation_info);
        System.out.println("sni: " + (sn == null ? "off" : "on"));
        System.out.println("renego: " + (rn == null ? "off" : "on"));
        System.out.println("heartbeat: " + (hb == null ? "off" : "on"));
        bugs.testBug(to);

    }

}
