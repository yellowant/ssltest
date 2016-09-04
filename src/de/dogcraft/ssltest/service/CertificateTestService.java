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
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x509.Certificate;

import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.PEM;

public class CertificateTestService extends TestService {

    public static class CACache {

        private final Set<CertificateWrapper> CAs = new HashSet<>();

        private final Set<CertificateWrapper> unmod = Collections.unmodifiableSet(CAs);

        public CACache(CertCache cc) {
            load(cc, new File("crtcache"), "");
            cc.clean();
        }

        public Set<CertificateWrapper> getCAs() {
            return unmod;
        }

        private void load(CertCache cc, File file, String string) {
            if (null == file) {
                return;
            }
            File[] files = file.listFiles();
            if (null == files) {
                return;
            }
            for (File f : files) {
                if (f.isDirectory()) {
                    load(cc, f, string + f.getName());
                } else if (f.getName().endsWith(".crt")) {
                    String fp = string + f.getName().split("\\.", 2)[0];
                    CertificateWrapper cw = cc.get(fp);
                    if (cw == null) {
                        System.out.println("Not found?: " + f + " as " + fp);
                        continue;
                    }
                    wouldLike(cw);
                } else {
                    System.out.println("Malformed File?: " + f);
                }
            }
        }

        public void wouldLike(CertificateWrapper cw) {
            if (cw.isCA()) {
                synchronized (unmod) {
                    CAs.add(cw);
                }
            }
        }
    }

    public static class CertCache {

        private final HashMap<String, WeakReference<CertificateWrapper>> cacheFingerprint = new HashMap<>();

        private long lastClean = System.currentTimeMillis();

        public CertificateWrapper get(String fp) {
            WeakReference<CertificateWrapper> cw1 = cacheFingerprint.get(fp);
            if (cw1 != null) {
                CertificateWrapper cw = cw1.get();
                if (cw != null) {
                    return cw;
                }
            }

            File f = getPath(fp);
            if (f.exists()) {
                return recover(f);
            }

            return null;
        }

        public synchronized void clean() {
            if (System.currentTimeMillis() - lastClean < 60 * 60 * 1000) {
                return;
            }
            lastClean = System.currentTimeMillis();
            Iterator<Entry<String, WeakReference<CertificateWrapper>>> i = cacheFingerprint.entrySet().iterator();
            while (i.hasNext()) {
                if (i.next().getValue().get() == null) {
                    i.remove();
                }
            }
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
                    throw new IOException("Malformed Header!: " + parts[0]);
                }
                String fp = parts[0].substring("issuer:".length());

                byte[] cert = PEM.decode("CERTIFICATE", parts[1]);
                Certificate c = Certificate.getInstance(cert);

                CertificateWrapper cw;
                if (fp.equals("self")) {
                    cw = new CertificateWrapper(c);
                } else if (fp.equals("null")) {
                    cw = new CertificateWrapper(c, null);
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
            return cacheFingerprint.put(cw.getHash(), new WeakReference<CertificateWrapper>(cw)) == null;
        }

        public void put(CertificateWrapper wrap) {
            CertificateWrapper cw = get(wrap.getHash());
            if (cw != null && cw.getIssuer() != null && wrap.getIssuer() == null) {
                return;
            }
            if (putInternal(wrap)) {
                ca.wouldLike(wrap);
                String hash = wrap.getHash();

                File f = getPath(hash);
                if ( !f.exists()) {
                    store(wrap, f);
                }
            }
        }

        private void store(CertificateWrapper wrap, File f) {
            f.getParentFile().mkdirs();
            System.out.println(f.getParentFile());

            try (Writer w = new OutputStreamWriter(new FileOutputStream(f), "UTF-8")) {
                if (wrap.isSelfsigned()) {
                    w.write("issuer:self\n");
                } else if (wrap.getIssuerWrapper() != null) {
                    w.write("issuer:" + wrap.getIssuerWrapper().getHash() + "\n");
                    store(wrap.getIssuerWrapper(), getPath(wrap.getIssuerWrapper().getHash()));
                } else {
                    w.write("issuer:null\n");
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

    private static final CACache ca = new CACache(cache);

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

    public static Set<CertificateWrapper> getCAs() {
        return ca.getCAs();
    }

}
