package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CertificateTestService extends TestService {

    @SuppressWarnings("deprecation")
    public void performTest(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        super.performTest(req, resp, useEventStream);

        String fp = req.getParameter("fp");

        // Some checks for this fingerprint to exist in our cache/database

        PrintStream ps = new PrintStream(resp.getOutputStream(), true);
        ps.println("retry: 10000");
        ps.println();

        /*
         * TestingSession to; { boolean observingOnly = false; synchronized
         * (cacheTestSession) { String lookupKey = ip + "#" + u.getHost() + ":"
         * + u.getProtocol() + "-" + u.getPort(); to =
         * cacheTestSession.get(lookupKey); if (to == null) { to = new
         * TestingSession(u.getHost(), ip, u.getPort(), u.getProtocol());
         * cacheTestSession.put(lookupKey, to); } else { observingOnly = true; }
         * } to.attach(ps); if (observingOnly) { to.waitForCompletion(); return;
         * } } to.performTest();
         */

    }

}
