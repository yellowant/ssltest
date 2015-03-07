package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

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

    HashMap<String, List<String>> cacheHostIPs = new HashMap<>();

    HashMap<String, TestingSession> cacheTestSession = new HashMap<>();

    @SuppressWarnings("deprecation")
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
        if (portStr == null || portStr.trim().equals("")) {
            portStr = "443";
            return;
        }

        String proto = "direct";
        try {
            if (portStr.indexOf('-') != -1) {
                proto = portStr.split("-", 2)[0];
                portStr = portStr.split("-", 2)[1];
            }
            portStr = String.format("%d", Integer.parseInt(portStr));
        } catch (NumberFormatException nfe) {
            resp.sendError(401, "Fuck off");
            return;
        }

        List<String> iplist;

        synchronized (cacheHostIPs) {
            iplist = cacheHostIPs.get(domain);
            if (iplist == null) {
                iplist = new ArrayList<String>();

                InetAddress[] addrlist = InetAddress.getAllByName(domain);
                for (InetAddress addr : addrlist) {
                    iplist.add(addr.getHostAddress());
                }
                cacheHostIPs.put(domain, iplist);
            }
        }

        String ip = req.getParameter("ip");
        if ((ip != null) && !iplist.contains(ip)) {
            resp.setStatus(404, "Host not found at this location");
        }

        PrintStream ps = new PrintStream(resp.getOutputStream(), true);
        ps.println("retry: 10000");
        ps.println();

        if (null == ip) {
            for (String hostip : iplist) {
                ps.println("event: hostip");
                ps.println("data: {");
                ps.println("data: domain: \"" + domain + "\"");
                ps.println("data: port: \"" + proto + "-" + portStr + "\"");
                ps.println("data: ip: \"" + hostip + "\"");
                ps.println("data: }");
                ps.println();
            }

            ps.println("event: eof");
            ps.println("data: {");
            ps.println("data: msg: \"IP lookup completed.\"");
            ps.println("data: }");
            ps.println();
            return;
        } else if ( !iplist.contains(ip)) {
            ps.println("event: eof");
            ps.println("data: {");
            ps.println("data: msg: \"Host not found at this address.\"");
            ps.println("data: }");
            ps.println();
            return;
        }

        TestingSession to;
        {
            String host = domain + ":" + portStr;
            boolean observingOnly = false;

            synchronized (cacheTestSession) {
                String lookupKey = ip + "#" + host;

                to = cacheTestSession.get(lookupKey);
                if (to == null) {
                    to = new TestingSession(domain, Integer.parseInt(portStr), proto);
                    cacheTestSession.put(lookupKey, to);
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

        to.performTest();
    }
}
