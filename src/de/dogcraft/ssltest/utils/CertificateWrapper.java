package de.dogcraft.ssltest.utils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.bouncycastle.asn1.x509.Certificate;

public class CertificateWrapper {

    Certificate c;

    String pkHash;

    String hash;

    private static final MessageDigest md;

    static {
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (GeneralSecurityException e) {
            throw new Error(e);
        }
    }

    public CertificateWrapper(Certificate c) {
        this.c = c;
        synchronized (md) {
            try {
                hash = TruststoreUtil.outputFingerprint(c, md);
                pkHash = TruststoreUtil.outputPKFingerprint(c, md);
            } catch (IOException e) {
                throw new Error(e);
            }
        }
    }

    public Certificate getC() {
        return c;
    }

    public String getHash() {
        return hash;
    }

    public String getPkHash() {
        return pkHash;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((hash == null) ? 0 : hash.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertificateWrapper other = (CertificateWrapper) obj;
        if (hash == null) {
            if (other.hash != null)
                return false;
        } else if ( !hash.equals(other.hash))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return c.getSubject().toString();
    }
}
