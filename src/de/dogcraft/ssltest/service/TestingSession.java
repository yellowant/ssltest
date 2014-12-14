package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintStream;
import java.util.LinkedList;
import java.util.ListIterator;

import org.bouncycastle.crypto.tls.ExtensionType;

import de.dogcraft.ssltest.tests.CertificateTest;
import de.dogcraft.ssltest.tests.TestCipherList;
import de.dogcraft.ssltest.tests.TestImplementationBugs;
import de.dogcraft.ssltest.tests.TestOutput;
import de.dogcraft.ssltest.tests.TestResult;

public class TestingSession extends TestOutput {

    private String host;

    private int port;

    private StringBuffer strb = new StringBuffer();

    private boolean ended;

    private LinkedList<PrintStream> interestedParties = new LinkedList<>();

    public TestingSession() {}

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
        ended = true;
        synchronized (this) {
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
        TestImplementationBugs b = new TestImplementationBugs(host, port);
        b.testBug(this);
        byte[] sn = b.getExt().get(ExtensionType.server_name);
        byte[] hb = b.getExt().get(ExtensionType.heartbeat);
        byte[] rn = b.getExt().get(ExtensionType.renegotiation_info);
        output("renego: " + (rn == null ? "off" : "on"));
        output("heartbeat: " + (hb == null ? "off" : "on"));

        boolean testCompression = b.testDeflate(this);
        if (testCompression) {
            output("Does support tls compression. ", -10);
        } else {
            output("Does not support tls compression.");
        }

        CertificateTest.testCerts(this, b);
    }

    private void determineCiphers(TestCipherList c) {
        String[] ciph = c.determineCiphers(this);
        if (c.hasServerPref()) {
            output("Server has cipher preference.");
        } else {
            output("Server has no cipher preference.");
        }
    }

    public void performTest() {
        try {
            System.out.println("Testing " + host + ":" + port);
            output("Testing " + host + ":" + port);

            try {
                testBugs();
            } catch (IOException e) {
                e.printStackTrace();
            }

            TestCipherList c = new TestCipherList(host, port);
            enterTest("Determining cipher suites");
            determineCiphers(c);
            exitTest("Determining cipher suites", TestResult.IGNORE);
        } finally {
            end();
        }

    }

}
