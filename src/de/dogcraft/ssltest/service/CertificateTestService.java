package de.dogcraft.ssltest.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Reader;
import java.io.Writer;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x509.Certificate;

import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.PEM;

public class CertificateTestService extends TestService {

    public static class CertCache {

        private final HashMap<String, CertificateWrapper> cacheFingerprint = new HashMap<>();

        public CertificateWrapper get(String fp) {
            CertificateWrapper cw = cacheFingerprint.get(fp);
            if (cw != null) {
                return cw;
            }

            File f = getPath(fp);
            if (f.exists()) {
                return recover(f);
            }

            return null;
        }

        private CertificateWrapper recover(File f) {
            StringBuffer b = new StringBuffer();
            try (Reader r = new InputStreamReader(new FileInputStream(f), "UTF-8")) {
                int d;
                char[] data = new char[4096];
                while ((d = r.read(data)) > 0) {
                    b.append(data, 0, d);
                }

                String[] parts = b.toString().split("\n", 2);
                if ( !parts[0].startsWith("issuer:")) {
                    throw new IOException("Malformed Header!");
                }
                String fp = parts[0].substring("issuer:".length());

                byte[] cert = PEM.decode("CERTIFICATE", parts[1]);
                Certificate c = Certificate.getInstance(cert);

                CertificateWrapper cw;
                if (fp.equals("self")) {
                    cw = new CertificateWrapper(c);
                } else {
                    cw = new CertificateWrapper(c, recover(getPath(fp)));
                }

                putInternal(cw);

                return cw;
            } catch (IOException e) {
                e.printStackTrace();
            }

            return null;
        }

        private boolean putInternal(CertificateWrapper cw) {
            return cacheFingerprint.put(cw.getHash(), cw) == null;
        }

        public void put(CertificateWrapper wrap) {
            CertificateWrapper cw = get(wrap.getHash());
            if (cw != null && cw.getIssuer() != null && wrap.getIssuer() == null) {
                return;
            }
            if (putInternal(wrap)) {
                String hash = wrap.getHash();

                File f = getPath(hash);
                if ( !f.exists()) {
                    store(wrap, f);
                }
            }
        }

        private void store(CertificateWrapper wrap, File f) {
            f.getParentFile().mkdirs();

            try (Writer w = new OutputStreamWriter(new FileOutputStream(f), "UTF-8")) {
                if (wrap.isSelfsigned()) {
                    w.write("issuer:self\n");
                } else {
                    w.write("issuer:" + wrap.getIssuerWrapper().getHash() + "\n");
                    store(wrap.getIssuerWrapper(), getPath(wrap.getIssuerWrapper().getHash()));
                }
                w.write(PEM.encode("CERTIFICATE", wrap.getC().getEncoded()));
                w.write("\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public File getPath(String fp) {
            return new File("crtcache/" + fp.substring(0, 2) + "/" + fp.substring(2, 4) + "/" + fp.substring(4, 8) + "/" + fp.substring(8) + ".crt");
        }
    }

    private static final HashMap<String, CertificateTestingSession> cacheSession = new HashMap<>();

    private static final CertCache cache = new CertCache();

    private static final Pattern patternFingerprint = Pattern.compile("[0-9a-f]{128}", Pattern.CASE_INSENSITIVE);

    @SuppressWarnings("deprecation")
    public void performTest(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        super.performTest(req, resp, useEventStream);

        String fp = req.getParameter("fp");

        fp = fp.toLowerCase();
        Matcher fpMatcher = patternFingerprint.matcher(fp);

        if ( !fpMatcher.matches()) {
            resp.setStatus(400, "Invalid fingerprint format. Please use SHA-512 fingerprint to continue.");
            return;
        }

        CertificateWrapper c;
        synchronized (cache) {
            c = cache.get(fp);
            if (c == null) {
                // Some checks for this fingerprint to exist in our
                // cache/database

                resp.sendError(404);
                return;
            }
        }

        PrintStream ps = new PrintStream(resp.getOutputStream(), true);
        ps.println("retry: 10000");
        ps.println();

        CertificateTestingSession to;
        {
            boolean observingOnly = false;
            synchronized (cacheSession) {
                to = cacheSession.get(fp);
                if (to == null) {
                    to = new CertificateTestingSession(c);
                    cacheSession.put(fp, to);
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
        synchronized (cache) {
            cache.put(wrap);
        }
    }

}
