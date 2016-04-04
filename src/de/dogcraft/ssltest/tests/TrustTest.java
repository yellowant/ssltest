package de.dogcraft.ssltest.tests;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;

import de.dogcraft.ssltest.service.CertificateTestService;
import de.dogcraft.ssltest.tests.TestCipherList.CertificateList;
import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.IOUtils;
import de.dogcraft.ssltest.utils.JSONUtils;
import de.dogcraft.ssltest.utils.PEM;
import de.dogcraft.ssltest.utils.Truststore;
import de.dogcraft.ssltest.utils.TruststoreGroup;

public class TrustTest {

    private static class CertificateIndex {

        HashMap<X500Name, HashSet<CertificateWrapper>> m = new HashMap<>();

        HashMap<CertificateWrapper, LinkedList<Truststore>> trust = new HashMap<>();

        public CertificateIndex(CertificateWrapper[] content) {
            for (CertificateWrapper certificate : content) {
                index(certificate);
            }
        }

        public CertificateIndex() {
            try {
                Map<String, TruststoreGroup> groups = TruststoreGroup.getStores();
                for (Entry<String, TruststoreGroup> e : groups.entrySet()) {
                    for (Entry<String, Truststore> e2 : e.getValue().getContainedTables().entrySet()) {
                        KeyStore ks = e2.getValue().getKeyStore();
                        Enumeration<String> aliases = ks.aliases();
                        while (aliases.hasMoreElements()) {
                            String alias = aliases.nextElement();
                            Certificate c = Certificate.getInstance(ks.getCertificate(alias).getEncoded());
                            index(new CertificateWrapper(c, null));
                            LinkedList<Truststore> l = trust.get(new CertificateWrapper(c, null));
                            if (l == null) {
                                l = new LinkedList<>();
                                trust.put(new CertificateWrapper(c, null), l);
                            }
                            l.add(e2.getValue());
                        }
                    }
                }
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        private void index(CertificateWrapper c) {
            X500Name ident = c.getC().getSubject();
            HashSet<CertificateWrapper> l = m.get(ident);
            if (l == null) {
                l = new HashSet<>();
                m.put(ident, l);
            }
            l.add(c);
        }

        public List<Truststore> getTrust(CertificateWrapper c) {
            LinkedList<Truststore> list = trust.get(c);
            if (list == null) {
                return Collections.emptyList();
            }
            return Collections.unmodifiableList(list);
        }

        public Set<CertificateWrapper> getIssuers(Certificate c) {
            Set<CertificateWrapper> list = m.get(c.getIssuer());
            if (list == null) {
                return Collections.emptySet();
            }
            return Collections.unmodifiableSet(list);
        }
    }

    private static final CertificateIndex ci = new CertificateIndex();

    private LinkedList<String> str = new LinkedList<>();

    private LinkedList<String> edges = new LinkedList<>();

    CertificateList chain;

    public TrustTest(CertificateList chain) {
        this.chain = chain;
    }

    public void test(TestOutput out) {
        Certificate toTrust = chain.content[0].getC();
        CertificateIndex local = new CertificateIndex(chain.content);
        LinkedList<CertificateWrapper> used = new LinkedList<>();
        CertificateWrapper e = new CertificateWrapper(toTrust, null);
        used.add(e);

        buildChains(out, e, local, used, false);

    }

    private void buildChains(TestOutput out, CertificateWrapper toTrustW, CertificateIndex local, LinkedList<CertificateWrapper> used, boolean trusted) {
        out.pushCert(toTrustW);
        Certificate toTrust = toTrustW.getC();
        Set<CertificateWrapper> localC = local.getIssuers(toTrust);
        Set<CertificateWrapper> globalC = ci.getIssuers(toTrust);
        for (CertificateWrapper certificate : localC) {
            if (used.contains(certificate) || !isIssuerOf(toTrust, certificate.getC())) {
                continue;
            }
            emitEdge(toTrustW, certificate, "chain");
            used.add(certificate);
            buildChains(out, certificate, local, used, trusted);
            used.removeLast();
        }
        for (Certificate c : getCAIssuer(toTrust, out)) {
            CertificateWrapper e = new CertificateWrapper(c, null);
            emitEdge(toTrustW, e, "issuer");
            used.add(e);
            buildChains(out, e, local, used, trusted);
            used.removeLast();
        }
        for (CertificateWrapper certificate : globalC) {
            if (used.contains(certificate) || !isIssuerOf(toTrust, certificate.getC())) {
                continue;
            }
            used.add(certificate);
            emitEdge(toTrustW, certificate, "trust");
            List<Truststore> trust = ci.getTrust(certificate);
            if ( !trusted) {
                emitChain(out, used, trust);
            }
            buildChains(out, certificate, local, used, true);
            used.removeLast();
        }
        Set<CertificateWrapper> cAs = CertificateTestService.getCAs();
        HashSet<CertificateWrapper> cacheFound = new HashSet<>();
        synchronized (cAs) {
            for (CertificateWrapper certificate : cAs) {
                if (used.contains(certificate) || !isIssuerOf(toTrust, certificate.getC())) {
                    continue;
                }
                cacheFound.add(certificate);
            }
        }
        for (CertificateWrapper certificate : cacheFound) {
            used.add(certificate);
            emitEdge(toTrustW, certificate, "cached");
            buildChains(out, certificate, local, used, true);
            used.removeLast();
        }
    }

    private void emitEdge(CertificateWrapper toTrust, CertificateWrapper e, String type) {
        edges.add("{\"chainId\":" + Integer.toString(chain.hashCode()) + ", \"from\":\"" + toTrust.getHash() + "\", \"to\":\"" + e.getHash() + "\", \"type\":\"" + type + "\"}");
    }

    private List<Certificate> getCAIssuer(Certificate toTrust, TestOutput out) {
        LinkedList<Certificate> l = new LinkedList<>();
        Extensions exts = toTrust.getTBSCertificate().getExtensions();
        if (exts == null)
            return l;
        Extension ext = exts.getExtension(Extension.authorityInfoAccess);
        if (ext == null)
            return l;
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
        AccessDescription[] data = aia.getAccessDescriptions();
        for (AccessDescription accessDescription : data) {
            GeneralName location = accessDescription.getAccessLocation();
            if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String value = DERIA5String.getInstance(location.getName()).getString();
                    try {
                        Certificate c = fetchCAIssuers(value, out);
                        if (isIssuerOf(toTrust, c)) {
                            l.add(c);
                        }
                    } catch (IllegalArgumentException e) {
                        e.printStackTrace(System.out);
                        System.out.println("Fetching " + value + " failed");
                    } catch (IOException e) {
                        e.printStackTrace(System.out);
                        System.out.println("Fetching " + value + " failed");
                    }
                }
            }
        }
        return l;
    }

    private boolean isIssuerOf(Certificate subject, Certificate issuer) {
        try {
            if ( !Arrays.equals(subject.getIssuer().getEncoded(), issuer.getSubject().getEncoded())) {
                return false;
            }
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            X509Certificate s = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(subject.getEncoded()));
            X509Certificate i = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(issuer.getEncoded()));
            s.verify(i.getPublicKey());
            Extensions e = subject.getTBSCertificate().getExtensions();
            if (e != null) {
                Extension eaki = e.getExtension(Extension.authorityKeyIdentifier);
                if (eaki != null) {
                    AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(eaki.getParsedValue());
                    if (aki.getAuthorityCertIssuer() != null) {
                        X500Name issuerN = X500Name.getInstance(aki.getAuthorityCertIssuer().getNames()[0].getName());
                        BigInteger serial = aki.getAuthorityCertSerialNumber();
                        if ( !Arrays.equals(issuerN.getEncoded(), issuer.getIssuer().getEncoded())) {
                            return false;
                        }
                        if ( !issuer.getTBSCertificate().getSerialNumber().toString().equals(serial.toString())) {
                            return false;
                        }
                    }
                }
            }
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return false;
    }

    private Certificate fetchCAIssuers(String value, TestOutput out) throws IOException {
        URL u = new URL(value);
        byte[] data = IOUtils.get(u);
        if (data[0] == '-') {
            data = PEM.decode("CERTIFICATE", new String(data, "UTF-8"));
            out.outputEvent("warning", "{\"msg\":\"" + JSONUtils.jsonEscape(value + " contains PEM-encoded cert.") + "\"}");
        }
        return Certificate.getInstance(data);

    }

    private void emitChain(TestOutput out, LinkedList<CertificateWrapper> used, List<Truststore> trust) {
        ArrayList<CertificateWrapper> cw = new ArrayList<>(used);
        Collections.reverse(cw);
        CertificateWrapper last = null;
        for (CertificateWrapper c : cw) {
            if (last != null) {
                last = new CertificateWrapper(c.getC(), last);
            } else {
                try {
                    if (Arrays.equals(c.getC().getIssuer().getEncoded(), c.getC().getSubject().getEncoded())) {
                        last = new CertificateWrapper(c.getC());
                    } else {
                        last = new CertificateWrapper(c.getC(), null);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        StringBuffer json = new StringBuffer();
        json.append("{ \"chainId\":");
        json.append(Integer.toString(chain.hashCode()));
        json.append(", \"certs\":[");
        boolean fst = true;
        for (CertificateWrapper cert : used) {
            if (fst) {
                fst = false;
            } else {
                json.append(", ");
            }
            json.append("\"" + cert.getHash() + "\"");
        }
        json.append("], \"stores\":[");
        fst = true;
        for (Truststore t : trust) {
            if (fst) {
                fst = false;
            } else {
                json.append(", ");
            }
            json.append("\"" + t.getName() + "\"");
        }
        json.append("]}");
        str.add(json.toString());
    }

    public void printChains(TestOutput out) {
        for (String string : str) {
            out.outputEvent("trustChain", string);
        }
        for (String string : edges) {
            out.outputEvent("trustEdge", string);
        }
    }
}
