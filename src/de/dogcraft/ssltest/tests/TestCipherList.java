package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.TreeSet;
import java.util.Vector;

import org.bouncycastle.crypto.tls.BugTestingTLSClient.CertificateObserver;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.CompressionMethod;
import org.bouncycastle.crypto.tls.TlsCipher;
import org.bouncycastle.crypto.tls.TlsCompression;
import org.bouncycastle.crypto.tls.TlsKeyExchange;

import de.dogcraft.ssltest.executor.TaskQueue;
import de.dogcraft.ssltest.tasks.CertificateChecker;
import de.dogcraft.ssltest.tests.TestingTLSClient.TLSCipherInfo;
import de.dogcraft.ssltest.utils.CipherProbingClient;
import de.dogcraft.ssltest.utils.JSONUtils;
import de.dogcraft.ssltest.utils.TruststoreUtil;

public class TestCipherList {

    private final String host;

    private Vector<Integer> ciphers = new Vector<>();

    private boolean serverPref = false;

    private static HashMap<Integer, String> cipherNames = new HashMap<>();

    private TestConnectionBuilder tcb;
    static {
        initCipherNames();
    }

    public TestCipherList(String host, TestConnectionBuilder tcb) {
        this.host = host;
        this.tcb = tcb;
    }

    private static void initCipherNames() {
        Field[] fs = CipherSuite.class.getFields();
        for (Field field : fs) {
            try {
                int int1 = field.getInt(null);
                if (int1 == 7)
                    continue;
                cipherNames.put(int1, field.getName());
            } catch (ReflectiveOperationException e) {
                e.printStackTrace();
            }
        }
    }

    public static Collection<Integer> getAllCiphers() {
        return new TreeSet<Integer>(cipherNames.keySet());
    }

    public Collection<Integer> getCiphers() {
        return ciphers;
    }

    public boolean hasServerPref() {
        return serverPref;
    }

    public String[] determineCiphers(TestOutput pw, TaskQueue tq) {
        LinkedList<TestResultCipher> yourCiphers = new LinkedList<>();
        Collection<Integer> ciphers = getAllCiphers();
        HashSet<CertificateList> chains = new HashSet<>();
        HashMap<String, CertificateChecker> map = new HashMap<>();

        try {
            for (int n = 0; n < ciphers.size(); n++) {
                TestResultCipher selection = choose(ciphers);
                if (selection == null) {
                    break;
                }
                yourCiphers.add(selection);

                selection.priority = n;
                CertificateList chain = new CertificateList(selection.chain.getCertificateList());
                if (chains.add(chain)) {
                    StringBuffer jsonChain = new StringBuffer();
                    for (int i = 0; i < chain.hashes.length; i++) {
                        if ( !map.containsKey(chain.hashes[i])) {
                            CertificateTest.testCerts(pw, chain.content[i]);
                            map.put(chain.hashes[i], null);
                        }

                        if (i != 0) {
                            jsonChain.append(", ");
                        }
                        jsonChain.append("\"");
                        jsonChain.append(JSONUtils.jsonEscape(chain.hashes[i]));
                        jsonChain.append("\"");
                    }
                    pw.outputEvent("chain", "{\"id\":" + chain.hashCode() + ", \"content\":[" + jsonChain.toString() + "]}");
                }
                pw.outputEvent("chainFound", String.format("{ \"cipherId\":\"%06x\", \"cipherName\":\"%s\", \"chainId\":%d}", selection.getCipherID(), JSONUtils.jsonEscape(selection.getCipherName()), chain.hashCode()));

                String cipherDesc = selection.toString();

                if (pw != null) {
                    pw.outputEvent("cipher", cipherDesc);
                }

                ciphers.remove(selection.cipherID);
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }

        int best = yourCiphers.get(0).getCipherID();
        int worst = yourCiphers.get(yourCiphers.size() - 1).getCipherID();

        int choice;
        try {
            choice = choose(Arrays.asList(worst, best)).getCipherID();
        } catch (IOException e) {
            choice = worst;
            e.printStackTrace();
        }

        serverPref = choice != worst;

        // TODO output was already made to the test output;
        // return chosen.toArray(new TestResultCipher[chosen.size()]);

        return new String[0];
    }

    private static class CertificateWrapper {

        org.bouncycastle.asn1.x509.Certificate c;

        String hash;

        public CertificateWrapper(org.bouncycastle.asn1.x509.Certificate c) throws NoSuchAlgorithmException, IOException {
            this.c = c;
            MessageDigest md = MessageDigest.getInstance("SHA1");
            hash = TruststoreUtil.outputFingerprint(c, md);
        }

        @Override
        public int hashCode() {
            return hash.hashCode();
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

    }

    private class CertificateList {

        org.bouncycastle.asn1.x509.Certificate[] content;

        String[] hashes;

        public CertificateList(org.bouncycastle.asn1.x509.Certificate[] content) throws NoSuchAlgorithmException, IOException {
            this.content = content;
            hashes = new String[content.length];
            MessageDigest md = MessageDigest.getInstance("SHA1");
            for (int i = 0; i < content.length; i++) {
                md.reset();
                hashes[i] = TruststoreUtil.outputFingerprint(content[i], md);
            }
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + getOuterType().hashCode();
            result = prime * result + Arrays.hashCode(hashes);
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
            CertificateList other = (CertificateList) obj;
            if ( !getOuterType().equals(other.getOuterType()))
                return false;
            if ( !Arrays.equals(hashes, other.hashes))
                return false;
            return true;
        }

        private TestCipherList getOuterType() {
            return TestCipherList.this;
        }

    }

    public class TestResultCipher {

        public int cipherID;

        public boolean supported;

        public int priority;

        public TlsKeyExchange kex;

        public TlsCompression compress;

        public TlsCipher cipher;

        public TLSCipherInfo info;

        public Certificate chain;

        public int getCipherID() {
            return cipherID;
        }

        public String getCipherName() {
            String resolved = TestCipherList.cipherNames.get(cipherID);
            return resolved;
        }

        public boolean getSupported() {
            return supported;
        }

        public int getPriority() {
            return priority;
        }

        protected void setCipherID(Integer cipherID) {
            this.cipherID = cipherID;
        }

        protected void setSupported(Boolean supported) {
            this.supported = supported;
        }

        protected void setPriority(Integer priority) {
            this.priority = priority;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            Formatter f = new Formatter(sb);

            try {
                f.format(//
                        "{ " + //
                                "\"cipherid\": \"%06x\", \"ciphername\": \"%s\", " + //
                                "\"kextype\": \"%s\", \"kexsize\": %d, " + //
                                "\"authtype\": \"%s\", \"authsize\": %d, " + //
                                "\"enctype\": \"%s\", \"encksize\": %d, \"encbsize\": %d, " + //
                                "\"mode\": \"%s\", " + //
                                "\"mactype\": \"%s\", \"macsize\": %d, " + //
                                "\"pfs\": \"%s\" " + //
                                "}", //
                        getCipherID(), JSONUtils.jsonEscape(getCipherName()), //
                        JSONUtils.jsonEscape(info.getKexType()), info.getKexSize(), //
                        JSONUtils.jsonEscape(info.getAuthKeyType()), info.getAuthKeySize(), //
                        JSONUtils.jsonEscape(info.getCipherType()), info.getCipherKSize(), info.getCipherBSize(), //
                        JSONUtils.jsonEscape(info.getCipherMode()), //
                        JSONUtils.jsonEscape(info.getMacType()), info.getMacSize(), //
                        info.isPFS() ? "yes" : "no");
            } finally {
                f.close();
            }

            return sb.toString();
        }
    }

    private TestResultCipher choose(final Collection<Integer> ciphers) throws IOException {
        Socket sock = tcb.spawn();
        final TestResultCipher resultCipher = new TestResultCipher();

        TestingTLSClient tcp = new TestingTLSClient(sock.getInputStream(), sock.getOutputStream());
        CipherProbingClient tc = new CipherProbingClient(host, ciphers, new short[] {
            CompressionMethod._null
        }, new CertificateObserver() {

            @Override
            public void onServerExtensionsReceived(Hashtable<Integer, byte[]> extensions) {

            }

            @Override
            public void onCertificateReceived(Certificate cert) {
                resultCipher.chain = cert;
            }
        });
        try {
            tcp.connect(tc);
            sock.getOutputStream().flush();
            tcp.close();
            sock.close();
        } catch (IOException e) {
        }

        int selectedCipherSuite = tc.getSelectedCipherSuite();
        if (selectedCipherSuite == 0) {
            return null;
        }

        if (tc.isFailed() || tcp.hasFailedLocaly()) {
            System.out.println("--- failed ---: " + cipherNames.get(selectedCipherSuite));
        }

        resultCipher.cipherID = selectedCipherSuite;
        resultCipher.priority = 0;
        resultCipher.supported = true;
        resultCipher.kex = tc.getKeyExchange();
        resultCipher.compress = tc.getCompression();
        // resultCipher.cipher = tc.getCipher();
        resultCipher.info = tcp.getCipherInfo();

        return resultCipher;
    }

}
