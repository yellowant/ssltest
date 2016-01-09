package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Service extends HttpServlet {

    private static final long serialVersionUID = 1L;

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
        } else if (path.equals("/about")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(Service.class.getResourceAsStream("../res/about.htm"), resp.getOutputStream());
        } else if (path.equals("/server.event")) {
            if (req.getParameter("domain") != null) {
                reqTestServer(req, resp, true);
            }
        } else if (path.equals("/server.txt")) {
            if (req.getParameter("domain") != null) {
                reqTestServer(req, resp, false);
            }
        } else if (path.equals("/cert.event")) {
            if (req.getParameter("fp") != null) {
                reqTestCertificate(req, resp, true);
            }
        } else if (path.equals("/cert.txt")) {
            if (req.getParameter("fp") != null) {
                reqTestCertificate(req, resp, false);
            }
        } else if (path.equals("/oid.js")) {
            OIDs.outputOids(resp);
        } else if (path.equals("/cipherRater.css")) {
            CipherRater.generateRateCSS(resp);
        } else {
            resp.sendError(404, "Fuck off");
        }
    }

    private void reqTestServer(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        ServerTestService sts = new ServerTestService();
        sts.performTest(req, resp, useEventStream);
    }

    private void reqTestCertificate(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        CertificateTestService cts = new CertificateTestService();
        cts.performTest(req, resp, useEventStream);
    }

}
