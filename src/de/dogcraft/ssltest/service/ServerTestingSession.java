package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Map.Entry;

import org.bouncycastle.crypto.tls.ExtensionType;

import de.dogcraft.ssltest.executor.TaskQueue;
import de.dogcraft.ssltest.executor.TaskQueue.Task;
import de.dogcraft.ssltest.tests.STARTTLS;
import de.dogcraft.ssltest.tests.TestCipherList;
import de.dogcraft.ssltest.tests.TestConnectionBuilder;
import de.dogcraft.ssltest.tests.TestImplementationBugs;
import de.dogcraft.ssltest.utils.JSONUtils;

public class ServerTestingSession extends TestingSession implements TestConnectionBuilder {

    private final String host;

    private final int port;

    private final String proto;

    private final String ip;

    TaskQueue tq = new TaskQueue();

    public ServerTestingSession(String host, String ip, int port, String proto) {
        this.host = host;
        this.ip = ip;
        this.port = port;
        this.proto = proto;
        outputEvent("streamID",
                "{\"host\":\"" + JSONUtils.jsonEscape(host) + "\", "//
                        + (ip == null ? "" : "\"ip\":\"" + JSONUtils.jsonEscape(ip) + "\", ")//
                        + "\"port\":" + port + ", \"proto\":\"" + JSONUtils.jsonEscape(proto) + "\"}");
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
                    Hashtable<Integer, byte[]> ext = b.getExt();
                    LinkedList<Integer> il = b.getIllegalExtensions();
                    HashSet<Integer> illegal;
                    if (il == null) {
                        illegal = new HashSet<>();
                    } else {
                        illegal = new HashSet<>(il);
                    }
                    StringBuffer res = new StringBuffer();
                    res.append("{");
                    if (null != ext) {
                        for (Entry<Integer, byte[]> c : ext.entrySet()) {
                            res.append("\"");
                            res.append(c.getKey());
                            res.append("\": {");
                            res.append("\"illegal\":\"");
                            res.append(illegal.contains(c.getKey()) ? "yes" : "no");
                            res.append("\"");
                            if (c.getKey() == ExtensionType.heartbeat) {
                                res.append(",\"tested\":" + hbTest);
                            }
                            res.append("},");
                        }
                        if (ext.get(ExtensionType.heartbeat) == null) {
                            res.append("\"");
                            res.append(ExtensionType.heartbeat);
                            res.append("\": {");
                            res.append("\"sent\": \"no\", \"illegal\":\"no\"");
                            res.append(",\"tested\":" + hbTest + "");
                            res.append("},");
                        }
                        res.deleteCharAt(res.length() - 1);
                    }
                    res.append("}");
                    outputEvent("extensions", //
                            res.toString());

                    boolean acceptsCompressionDeflate = b.testCompressionDeflate(ServerTestingSession.this);

                    boolean acceptsCompressionLZS = b.testCompressionLZS(ServerTestingSession.this);
                    if (acceptsCompressionDeflate || acceptsCompressionLZS) {
                        StringBuffer event = new StringBuffer("{ \"accepted\": \"yes\", \"algs\" : [");
                        if (acceptsCompressionDeflate) {
                            event.append("{ \"id\": 1, \"name\": \"DEFLATE\" }");
                        }
                        if (acceptsCompressionDeflate && acceptsCompressionLZS) {
                            event.append(", ");
                        }
                        if (acceptsCompressionLZS) {
                            event.append("{ \"id\": 64, \"name\": \"LZS\" }");
                        }
                        event.append("], \"points\": -10 }");
                        outputEvent("compression", event.toString());

                    } else {
                        outputEvent("compression", "{ \"accepted\": \"no\", \"algs\" : [], \"points\": 0 }");
                    }
                } catch (ConnectException e) {
                    outputEvent("error", "{ \"message\": \"connection failed\" }");
                    end();
                    throw new TaskQueue.TaskQueueAbortedException(e);
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
        outputEvent("test",
                String.format("{ \"ip\": \"%s\", \"host\": \"%s\", \"port\": \"%d\", \"proto\": \"%s\" }", //
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
                TestCipherList c = new TestCipherList(host, ServerTestingSession.this);
                c.determineCiphers(ServerTestingSession.this, tq);
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
