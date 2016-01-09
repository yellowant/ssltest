package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import de.dogcraft.ssltest.utils.CertificateWrapper;

public class CertificateTestService extends TestService {

    protected static HashMap<String, CertificateTestingSession> cacheTestSession = new HashMap<>();

    private static final HashMap<String, CertificateWrapper> cache = new HashMap<>();

    @SuppressWarnings("deprecation")
    public void performTest(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        super.performTest(req, resp, useEventStream);

        String fp = req.getParameter("fp");
        fp = fp.toLowerCase();
        if ( !fp.matches("[a-f0-9]+")) {
            resp.sendError(404);
            return;
        }
        CertificateWrapper c = cache.get(fp);
        if (c == null) {
            resp.sendError(404);
            return;
        }

        // Some checks for this fingerprint to exist in our cache/database

        PrintStream ps = new PrintStream(resp.getOutputStream(), true);
        ps.println("retry: 10000");
        ps.println();

        CertificateTestingSession to;
        {
            boolean observingOnly = false;
            synchronized (cacheTestSession) {
                to = cacheTestSession.get(fp);
                if (to == null) {
                    to = new CertificateTestingSession(c);
                    cacheTestSession.put(fp, to);
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

    public static void cache(CertificateWrapper wrap) {
        cache.put(wrap.getHash(), wrap);
    }

}
