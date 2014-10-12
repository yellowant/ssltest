package de.dogcraft.ssltest.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class Truststore {

    KeyStore ks;

    public Truststore() throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance("JKS");
        ks.load(null);
    }

    public Truststore(File f, HashMap<String, Truststore> storesm) throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance("JKS");
        File ksF = new File(f.getAbsolutePath() + ".jks");
        if (ksF.exists()) {
            ks.load(new FileInputStream(ksF), "changeit".toCharArray());
        } else {
            ks.load(null);
            if (f.exists()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                for (File f1 : f.listFiles()) {
                    X509Certificate crt = (X509Certificate) cf.generateCertificate(new FileInputStream(f1));
                    md.reset();
                    ks.setCertificateEntry(TruststoreUtil.outputFingerprint(crt, md), crt);
                }
            } else if (f.getName().equals("any")) {
                for (Truststore i : storesm.values()) {
                    Enumeration<String> al = i.ks.aliases();
                    while (al.hasMoreElements()) {
                        put(i.ks.getCertificate(al.nextElement()));
                    }
                }
            }
            ks.store(new FileOutputStream(ksF), "changeit".toCharArray());
        }
    }

    public void put(Certificate c) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        ks.setCertificateEntry(TruststoreUtil.outputFingerprint(c, md), c);
    }

    public void store(File f) throws GeneralSecurityException, IOException {
        ks.store(new FileOutputStream(f), "changeit".toCharArray());
    }

    public KeyStore getKeyStore() {
        return ks;
    }

    private static final Map<String, Truststore> stores;
    static {
        HashMap<String, Truststore> storesm = new HashMap<>();
        File f = new File("trusts");
        for (File fs : f.listFiles()) {
            if ( !fs.isDirectory() || fs.getName().startsWith("_")) {
                continue;
            }
            try {
                Truststore ts = new Truststore(fs, storesm);
                storesm.put(fs.getName(), ts);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try {
            Truststore any = new Truststore(new File("trusts/any"), storesm);
            storesm.put("any", any);
        } catch (GeneralSecurityException e) {
            throw new Error(e);
        } catch (IOException e) {
            throw new Error(e);
        }
        stores = Collections.unmodifiableMap(storesm);

    }

    public static Map<String, Truststore> getStores() {
        return stores;
    }

    public static void main(String[] args) {

    }

    public boolean contains(Certificate c) {
        try {
            return c.equals(ks.getCertificate(TruststoreUtil.outputFingerprint(c, MessageDigest.getInstance("SHA-512"))));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

}
