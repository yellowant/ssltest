package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.LinkedList;
import java.util.ListIterator;

import org.bouncycastle.crypto.tls.ExtensionType;

import de.dogcraft.ssltest.tests.CertificateTest;
import de.dogcraft.ssltest.tests.STARTTLS;
import de.dogcraft.ssltest.tests.TestCipherList;
import de.dogcraft.ssltest.tests.TestConnectionBuilder;
import de.dogcraft.ssltest.tests.TestImplementationBugs;
import de.dogcraft.ssltest.tests.TestOutput;
import de.dogcraft.ssltest.tests.TestResult;
import de.dogcraft.ssltest.utils.JSONUtils;

public class TestingSession extends TestOutput implements TestConnectionBuilder {

    private final String host;

    private final int port;

    private final String proto;

    private final String ip;

    private StringBuffer strb = new StringBuffer();

    private boolean ended;

    private LinkedList<PrintStream> interestedParties = new LinkedList<>();

    public TestingSession(String host, String ip, int port, String proto) {
        this.host = host;
        this.ip = ip;
        this.port = port;
        this.proto = proto;
    }

    public synchronized void attach(PrintStream target) {
        target.print(strb.toString());
        target.flush();
        if ( !ended) {
            interestedParties.add(target);
        }
    }

    @Override
    public synchronized void println(String s) {
        strb.append(s);
        strb.append('\n');

        ListIterator<PrintStream> it = interestedParties.listIterator();
        while (it.hasNext()) {
            PrintStream ps = it.next();
            if (ps.checkError()) {
                it.remove();
                continue;
            }
            ps.println(s);
        }
    }

    @Override
    public void end() {
        super.end();
        synchronized (this) {
            ended = true;
            notifyAll();
        }
    }

    public synchronized void waitForCompletion() {
        while ( !ended) {
            try {
                wait();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void testBugs() throws IOException {
        TestImplementationBugs b = new TestImplementationBugs(host, this);
        b.testBug(this);
        byte[] sn = b.getExt().get(ExtensionType.server_name);
        byte[] hb = b.getExt().get(ExtensionType.heartbeat);
        byte[] rn = b.getExt().get(ExtensionType.renegotiation_info);
        outputEvent("renegotiation", //
                String.format("{ \"secure_renego\": \"%s\" }", //
                        rn == null ? "yes" : "no"));
        outputEvent("heartbeat", //
                String.format("{ \"heartbeat\": \"%s\", \"heartbleed\": \"%s\" }", //
                        hb != null ? "yes" : "no", "unknown"));
        outputEvent("sni", //
                String.format("{ \"sni\": \"%s\" }", //
                        sn == null ? "no" : "yes"));

        boolean supportsCompression = true;
        if (supportsCompression) {
            boolean acceptsCompression = b.testDeflate(this);

            if (acceptsCompression) {
                outputEvent("compression", "{ \"supported\": \"yes\", \"accepted\": \"yes\", \"points\": -10 }");
            } else {
                outputEvent("compression", "{ \"supported\": \"yes\", \"accepted\": \"no\", \"points\": 0 }");
            }
        } else {
            outputEvent("compression", "{ \"supported\": \"no\", \"accepted\": \"no\", \"points\": -5 }");
        }

        CertificateTest.testCerts(this, b);
    }

    private void determineCiphers(TestCipherList c) {
        c.determineCiphers(this);

        if (c.hasServerPref()) {
            outputEvent("cipherpref", "{ \"cipherpref\": \"yes\" }");
        } else {
            outputEvent("cipherpref", "{ \"cipherpref\": \"no\" }");
        }
    }

    public void performTest() {
        try {
            System.out.println("Testing " + ip + "#" + host + ":" + port);
            System.out.println("Proto: " + proto);
            outputEvent("test", String.format("{ \"ip\": \"%s\", \"host\": \"%s\", \"port\": \"%d\", \"proto\": \"%s\" }", //
                    JSONUtils.jsonEscape(ip), //
                    JSONUtils.jsonEscape(host), //
                    port, JSONUtils.jsonEscape(proto)));

            try {
                testBugs();
            } catch (IOException e) {
                e.printStackTrace();
            }

            TestCipherList c = new TestCipherList(host, this);
            enterTest("Determining cipher suites");
            determineCiphers(c);
            exitTest("Determining cipher suites", TestResult.IGNORE);
        } finally {
            end();
        }

    }

    @Override
    public Socket spawn() throws IOException {
        return STARTTLS.starttls(new Socket(ip, port), proto, host);
    }

}
