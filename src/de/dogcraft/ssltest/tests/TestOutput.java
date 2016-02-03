package de.dogcraft.ssltest.tests;

import java.util.HashMap;
import java.util.concurrent.LinkedBlockingDeque;

import de.dogcraft.ssltest.service.CertificateTestService;
import de.dogcraft.ssltest.utils.CertificateWrapper;

public abstract class TestOutput {

    private class TestExecution {

        String name;

        public TestExecution(String name) {
            this.name = name;
        }

        HashMap<String, TestResult> map;

        public void add(String name, TestResult tr) {
            if (TestResult.IGNORE == tr) {
                return;
            }
            if (map == null) {
                map = new HashMap<>();
            }
            map.put(name, tr);
        }

        public String getName() {
            return name;
        }

        public HashMap<String, TestResult> getMap() {
            return map;
        }
    }

    LinkedBlockingDeque<TestExecution> queue = new LinkedBlockingDeque<>();

    public TestOutput() {
        queue.add(new TestExecution("root"));
    }

    public void enterTest(String testName) {
        outputEvent("enter", testName);
        queue.push(new TestExecution(testName));
    }

    public abstract void println(String s);

    public void exitTest(String testName, TestResult res) {
        TestExecution poll = queue.poll();
        if ( !poll.getName().equals(testName)) {
            throw new Error(poll.getName() + " <=> " + testName);
        }

        queue.peek().add(testName, res);
        outputEvent("exit", testName + (res == null ? "" : " -> " + (Math.ceil(100 * res.getRes()))));
    }

    @Deprecated
    public void output(String message) {
        output(message, 0);
    }

    @Deprecated
    public void output(String message, int points) {
        println("data: " + message + (points == 0 ? "" : " (" + points + ")"));
        println("");
    }

    public void finest(String message) {

    }

    public void end() {
        outputEvent("eof", "{}");
    }

    public HashMap<String, TestResult> getSubresults() {
        return queue.peek().getMap();
    }

    public void outputEvent(String event, String details) {
        println("event: " + event);
        String[] lines = details.split("\n");
        for (String line : lines) {
            println("data: " + line);
        }
        println("");
    }

    public void pushCert(CertificateWrapper certificate) {
        System.out.println("push: " + certificate.getHash());
        CertificateTestService.cache(certificate);
    }

}
