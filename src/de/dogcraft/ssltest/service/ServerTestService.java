package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import de.dogcraft.ssltest.utils.JSONUtils;
import de.dogcraft.ssltest.utils.URLParsing;
import de.dogcraft.ssltest.utils.URLParsing.TestParameter;
import de.dogcraft.ssltest.utils.URLParsing.TestParameterParsingException;

class ServerTestService extends TestService {

    protected static HashMap<String, List<String>> cacheHostIPs = new HashMap<>();

    protected static HashMap<String, TestingSession> cacheTestSession = new HashMap<>();

    @SuppressWarnings("deprecation")
    public void performTest(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        super.performTest(req, resp, useEventStream);

        TestParameter u;
        try {
            u = URLParsing.parse(req);
            String port = u.getProtocol() + "-" + Integer.toString(u.getPort());
            if ( !u.getHost().equals(req.getParameter("domain")) || !port.equals(req.getParameter("port"))) {
                // Input has been canonicalized, send redirect.
                String ip = req.getParameter("ip");
                String url = req.getPathInfo() + "?domain=" + URLEncoder.encode(u.getHost(), "UTF-8")//
                        + "&port=" + URLEncoder.encode(port, "UTF-8")//
                        + (ip != null ? "&ip" + URLEncoder.encode(ip, "UTF-8") : "");

                resp.sendRedirect(url);
                return;
            }
        } catch (TestParameterParsingException e) {
            resp.sendError(404, e.getMessage());
            return;
        }

        List<String> iplist;

        synchronized (cacheHostIPs) {
            iplist = cacheHostIPs.get(u.getHost());
            if (iplist == null) {
                iplist = new ArrayList<String>();
                try {
                    InetAddress[] addrlist = InetAddress.getAllByName(u.getHost());
                    for (InetAddress addr : addrlist) {
                        iplist.add(addr.getHostAddress());
                    }
                } catch (UnknownHostException e) {
                    resp.sendError(404, e.getMessage());
                    return;
                }
                cacheHostIPs.put(u.getHost(), iplist);
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
            ps.println("event: streamID");
            ps.println("data: {\"host\":\"" + JSONUtils.jsonEscape(u.getHost()) + "\", "//
                    + "\"port\":" + u.getPort() + ", \"proto\":\"" + JSONUtils.jsonEscape(u.getProtocol()) + "\"}");
            ps.println();
            for (String hostip : iplist) {
                ps.println("event: hostip");
                ps.println("data: {");
                ps.println("data: \"domain\": \"" + JSONUtils.jsonEscape(u.getHost()) + "\",");
                ps.println("data: \"port\": \"" + JSONUtils.jsonEscape(u.getProtocol()) + "-" + JSONUtils.jsonEscape(Integer.toString(u.getPort())) + "\",");
                ps.println("data: \"ip\": \"" + JSONUtils.jsonEscape(hostip) + "\"");
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
            boolean observingOnly = false;

            synchronized (cacheTestSession) {
                String lookupKey = ip + "#" + u.getHost() + ":" + u.getProtocol() + "-" + u.getPort();

                to = cacheTestSession.get(lookupKey);
                if (to == null) {
                    to = new TestingSession(u.getHost(), ip, u.getPort(), u.getProtocol());
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
