package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.crypto.tls.ExtensionType;

import de.dogcraft.ssltest.tests.CertificateTest;
import de.dogcraft.ssltest.tests.TestCipherList;
import de.dogcraft.ssltest.tests.TestImplementationBugs;
import de.dogcraft.ssltest.tests.TestOutput;
import de.dogcraft.ssltest.tests.TestResult;

public class Service extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

    private static void copyStream(InputStream in, OutputStream out) {
        try {
            try {
                try {
                    int len;
                    byte[] buf = new byte[65536];

                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } finally {
                    out.close();
                }
            } finally {
                in.close();
            }
        } catch (IOException e) {
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setCharacterEncoding("UTF-8");

        String path = req.getPathInfo();
        if (path == null || path.equals("/")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(Service.class.getResourceAsStream("../res/index.htm"), resp.getOutputStream());
        } else if (path.equals("/client.js")) {
            resp.setContentType("text/javascript");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(Service.class.getResourceAsStream("../res/client.js"), resp.getOutputStream());
        } else if (path.equals("/client.css")) {
            resp.setContentType("text/css");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(Service.class.getResourceAsStream("../res/client.css"), resp.getOutputStream());
        } else if (path.equals("/test.event")) {
            if (req.getParameter("domain") != null) {
                stream(req, resp, true);
            }
        } else if (path.equals("/test.txt")) {
            if (req.getParameter("domain") != null) {
                stream(req, resp, false);
            }
        } else {
            resp.sendError(404, "Fuck off");
        }
    }

    HashMap<String, TestingSession> cache = new HashMap<>();

    private void stream(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        if (useEventStream) {
            resp.setContentType("text/event-stream");
        } else {
            resp.setContentType("text/plain");
        }

        String domain = req.getParameter("domain");
        if (null == domain) {
            resp.sendError(500, "error params missing");
            return;
        }

        String portStr = req.getParameter("port");
        int port;
        if (portStr == null) {
            portStr = "443";
            return;
        }
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException nfe) {
            resp.sendError(401, "Fuck off");
            return;
        }

        TestingSession to;
        {
            PrintStream ps = new PrintStream(resp.getOutputStream(), true);
            ps.println("retry: 10000");
            ps.println();

            String host = domain + ":" + portStr;
            boolean observingOnly = false;

            synchronized (cache) {
                to = cache.get(host);
                if (to == null) {
                    to = new TestingSession();
                    cache.put(host, to);
                } else {
                    observingOnly = true;
                }
            }

            to.attach(ps);

            if (observingOnly) {
                to.waitForCompletion();
                return;
            }
        }

        try {
            System.out.println("Testing " + domain + ":" + port);
            to.output("Testing " + domain + ":" + port);

            TestImplementationBugs b = new TestImplementationBugs(domain, port);
            testBugs(b, to);
            CertificateTest.testCerts(to, b);

            boolean testCompression = b.testDeflate(to);
            if (testCompression) {
                to.output("Does support tls compression. ", -10);
            } else {
                to.output("Does not support tls compression.");
            }

            TestCipherList c = new TestCipherList(domain, port);
            to.enterTest("Determining cipher suites");
            determineCiphers(to, c);
            to.exitTest("Determining cipher suites", TestResult.IGNORE);
        } finally {
            to.end();
        }
    }

    private void testBugs(TestImplementationBugs b, TestOutput ps) throws IOException {
        b.testBug(ps);
        byte[] sn = (byte[]) b.getExt().get(ExtensionType.server_name);
        byte[] hb = (byte[]) b.getExt().get(ExtensionType.heartbeat);
        byte[] rn = (byte[]) b.getExt().get(ExtensionType.renegotiation_info);
        ps.output("renego: " + (rn == null ? "off" : "on"));
        ps.output("heartbeat: " + (hb == null ? "off" : "on"));
    }

    private void determineCiphers(TestOutput ps, TestCipherList c) throws IOException {
        String[] ciph = c.determineCiphers(ps);
        if (c.hasServerPref()) {
            ps.output("Server has cipher preference.");
        } else {
            ps.output("Server has no cipher preference.");
        }
    }

}
