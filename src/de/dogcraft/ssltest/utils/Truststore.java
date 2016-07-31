package de.dogcraft.ssltest.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Truststore {

    KeyStore ks;

    TruststoreGroup myGroup;

    private String name;

    public Truststore() throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance("JKS");
        ks.load(null);
    }

    public void initAny(Iterable<TruststoreGroup> collection) throws GeneralSecurityException, IOException {
        File ksF = new File("trusts/any.jks");
        if (ksF.exists()) {
            ks.load(new FileInputStream(ksF), "changeit".toCharArray());
        } else {
            for (TruststoreGroup i : collection) {
                for (Truststore ts : i.tm.values()) {
                    Enumeration<String> al = ts.ks.aliases();
                    while (al.hasMoreElements()) {
                        put(ts.ks.getCertificate(al.nextElement()));
                    }
                }
            }
            ks.store(new FileOutputStream(ksF), "changeit".toCharArray());
        }

    }

    public Truststore(File f, TruststoreGroup group, String name) throws GeneralSecurityException, IOException {
        myGroup = group;
        this.name = name;
        ks = KeyStore.getInstance("JKS");
        File ksF = new File(f.getAbsolutePath() + ".jks");
        if (ksF.exists()) {
            ks.load(new FileInputStream(ksF), "changeit".toCharArray());
        } else {
            ks.load(null);
            if (f.exists()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                MessageDigest md = MessageDigest.getInstance("SHA-512");

                File[] fl = f.listFiles(new FilenameFilter() {

                    @Override
                    public boolean accept(File dir, String name) {
                        return name.endsWith(".crt");
                    }

                });

                if (null == fl) {
                    fl = new File[0];
                }

                for (File f1 : fl) {
                    try {
                        FileInputStream inStream = new FileInputStream(f1);
                        X509Certificate crt = (X509Certificate) cf.generateCertificate(inStream);
                        inStream.close();
                        md.reset();
                        ks.setCertificateEntry(TruststoreUtil.outputFingerprint(crt, md), crt);
                    } catch (Exception e) {
                        System.out.println("Could not load certificate: " + f1.getAbsolutePath());
                        e.printStackTrace();
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

    public boolean contains(Certificate c) {
        try {
            return c.equals(ks.getCertificate(TruststoreUtil.outputFingerprint(c, MessageDigest.getInstance("SHA-512"))));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public boolean hasSameContents(Truststore last) throws KeyStoreException {
        Enumeration<String> en = ks.aliases();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if ( !last.ks.containsAlias(key)) {
                return false;
            }
        }
        Enumeration<String> en2 = last.ks.aliases();
        while (en2.hasMoreElements()) {
            String key = en2.nextElement();
            if ( !ks.containsAlias(key)) {
                return false;
            }
        }
        return true;
    }

    public String getName() {
        return name;
    }

}
