package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.LinkedList;
import java.util.ListIterator;

import org.bouncycastle.crypto.tls.ExtensionType;

import de.dogcraft.ssltest.executor.TaskQueue;
import de.dogcraft.ssltest.executor.TaskQueue.Task;
import de.dogcraft.ssltest.tests.STARTTLS;
import de.dogcraft.ssltest.tests.TestCipherList;
import de.dogcraft.ssltest.tests.TestConnectionBuilder;
import de.dogcraft.ssltest.tests.TestImplementationBugs;
import de.dogcraft.ssltest.tests.TestOutput;
import de.dogcraft.ssltest.utils.JSONUtils;

public class TestingSession extends TestOutput implements TestConnectionBuilder {

    private final String host;

    private final int port;

    private final String proto;

    private final String ip;

    private StringBuffer strb = new StringBuffer();

    private boolean ended;

    private LinkedList<PrintStream> interestedParties = new LinkedList<>();

    TaskQueue tq = new TaskQueue();

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

    private Task testBugs() {
        final TestImplementationBugs b = new TestImplementationBugs(host, this);
        final Task t1 = tq.new Task() {

            {
                requeue();
            }

            @Override
            public void run() {

                try {
                    String hbTest = b.testHeartbeat();
                    byte[] sn = b.getExt().get(ExtensionType.server_name);
                    byte[] hb = b.getExt().get(ExtensionType.heartbeat);
                    byte[] rn = b.getExt().get(ExtensionType.renegotiation_info);
                    outputEvent("renegotiation", //
                            String.format("{ \"secure_renego\": \"%s\" }", //
                                    rn == null ? "yes" : "no"));
                    outputEvent("heartbeat", //
                            String.format("{ \"heartbeat\": \"%s\", \"test\": %s }", //
                                    hb != null ? "yes" : "no", hbTest));
                    outputEvent("sni", //
                            String.format("{ \"sni\": \"%s\" }", //
                                    sn == null ? "no" : "yes"));

                    boolean supportsCompression = true;
                    if (supportsCompression) {
                        boolean acceptsCompression = b.testDeflate(TestingSession.this);

                        if (acceptsCompression) {
                            outputEvent("compression", "{ \"supported\": \"yes\", \"accepted\": \"yes\", \"points\": -10 }");
                        } else {
                            outputEvent("compression", "{ \"supported\": \"yes\", \"accepted\": \"no\", \"points\": 0 }");
                        }
                    } else {
                        outputEvent("compression", "{ \"supported\": \"no\", \"accepted\": \"no\", \"points\": -5 }");
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    throw new Error(e);
                }
            }

            @Override
            public String toString() {
                return "Task-bugs";
            }
        };
        return t1;
    }

    public void performTest() {
        System.out.println("Testing " + ip + "#" + host + ":" + port);
        System.out.println("Proto: " + proto);
        outputEvent("test", String.format("{ \"ip\": \"%s\", \"host\": \"%s\", \"port\": \"%d\", \"proto\": \"%s\" }", //
                JSONUtils.jsonEscape(ip), //
                JSONUtils.jsonEscape(host), //
                port, JSONUtils.jsonEscape(proto)));

        final Task bugs = testBugs();
        final Task ciphers = tq.new Task() {

            {
                dependsOn(bugs);
                requeue();
            }

            public void run() {
                TestCipherList c = new TestCipherList(host, TestingSession.this);
                c.determineCiphers(TestingSession.this, tq);

                if (c.hasServerPref()) {
                    outputEvent("cipherpref", "{ \"cipherpref\": \"yes\" }");
                } else {
                    outputEvent("cipherpref", "{ \"cipherpref\": \"no\" }");
                }
            }

            @Override
            public String toString() {
                return "Task-ciphers";
            }
        };
        tq.new Task() {

            {
                dependsOn(ciphers);
                requeue();
            }

            public void run() {
                end();

            }

            @Override
            public String toString() {
                return "Task-ending";
            }
        };
        waitForCompletion();

    }

    @Override
    public Socket spawn() throws IOException {
        return STARTTLS.starttls(new Socket(ip, port), proto, host);
    }

}
