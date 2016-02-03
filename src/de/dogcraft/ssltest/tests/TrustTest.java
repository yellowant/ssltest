package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;

import de.dogcraft.ssltest.tests.TestCipherList.CertificateList;
import de.dogcraft.ssltest.utils.CertificateWrapper;
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

    CertificateList chain;

    public TrustTest(CertificateList chain) {
        this.chain = chain;
    }

    public void test(TestOutput out) {
        Certificate toTrust = chain.content[0].getC();
        CertificateIndex local = new CertificateIndex(chain.content);
        LinkedList<CertificateWrapper> used = new LinkedList<>();
        used.add(new CertificateWrapper(toTrust, null));

        buildChains(out, toTrust, local, used);

    }

    private void buildChains(TestOutput out, Certificate toTrust, CertificateIndex local, LinkedList<CertificateWrapper> used) {
        Set<CertificateWrapper> localC = local.getIssuers(toTrust);
        Set<CertificateWrapper> globalC = ci.getIssuers(toTrust);
        for (CertificateWrapper certificate : localC) {
            if (used.contains(certificate)) {
                continue;
            }
            used.add(certificate);
            buildChains(out, certificate.getC(), local, used);
            used.removeLast();
        }
        for (CertificateWrapper certificate : globalC) {
            if (used.contains(certificate)) {
                continue;
            }
            used.add(certificate);
            List<Truststore> trust = ci.getTrust(certificate);
            emitChain(out, used, trust);
            used.removeLast();
        }
    }

    private void emitChain(TestOutput out, LinkedList<CertificateWrapper> used, List<Truststore> trust) {
        ArrayList<CertificateWrapper> cw = new ArrayList<>(used);
        Collections.reverse(cw);
        CertificateWrapper last = null;
        for (CertificateWrapper c : cw) {
            if (last != null) {
                out.pushCert(last = new CertificateWrapper(c.getC(), last));
            } else {
                try {
                    if (Arrays.equals(c.getC().getIssuer().getEncoded(), c.getC().getSubject().getEncoded())) {
                        out.pushCert(last = new CertificateWrapper(c.getC()));
                    } else {
                        out.pushCert(last = new CertificateWrapper(c.getC(), null));
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
        out.outputEvent("trustChain", json.toString());
    }
}
