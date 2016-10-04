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
import org.bouncycastle.crypto.tls.CipherConstants;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.CompressionMethod;
import org.bouncycastle.crypto.tls.TlsCipher;
import org.bouncycastle.crypto.tls.TlsCompression;
import org.bouncycastle.crypto.tls.TlsDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsPSKKeyExchange;
import org.bouncycastle.crypto.tls.TlsSRPKeyExchange;

import de.dogcraft.ssltest.executor.TaskQueue;
import de.dogcraft.ssltest.tasks.CertificateChecker;
import de.dogcraft.ssltest.tests.TestingTLSClient.TLSCipherInfo;
import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.CipherProbingClient;
import de.dogcraft.ssltest.utils.CipherProbingClient.BrokenCipherException;
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

    public static String resolveCipher(Integer i) {
        return cipherNames.get(i);
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
        ciphers.remove(org.bouncycastle.crypto.tls.CipherConstants.CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV.getValue());
        ciphers.remove(org.bouncycastle.crypto.tls.CipherConstants.CipherSuite.TLS_FALLBACK_SCSV.getValue());
        HashSet<CertificateList> chains = new HashSet<>();
        HashMap<String, CertificateChecker> map = new HashMap<>();

        try {
            for (int n = 0; 0 < ciphers.size(); n++) {
                TestResultCipher selection = choose(ciphers);
                if (selection == null) {
                    break;
                }
                yourCiphers.add(selection);
                ciphers.remove(selection.cipherID);

                selection.priority = n;
                int hash = 0;
                if (selection.getSupported()) {
                    CertificateList chain = new CertificateList(selection.chain.getCertificateList());
                    if (chains.add(chain)) {
                        StringBuffer jsonChain = new StringBuffer();
                        for (int i = 0; i < chain.hashes.length; i++) {
                            if ( !map.containsKey(chain.hashes[i])) {
                                map.put(chain.hashes[i], null);
                            }

                            if (i != 0) {
                                jsonChain.append(", ");
                            }
                            jsonChain.append("\"");
                            jsonChain.append(JSONUtils.jsonEscape(chain.hashes[i]));
                            jsonChain.append("\"");
                            pw.pushCert(chain.content[i]);
                        }
                        TrustTest tt = new TrustTest(chain);
                        tt.test(pw);
                        pw.outputEvent("chain", "{\"id\":" + chain.hashCode() + ", \"content\":[" + jsonChain.toString() + "]}");
                        for (CertificateWrapper certificateList : chain.content) {

                        }
                        tt.printChains(pw);
                    }
                    hash = chain.hashCode();
                }

                String cipherDesc = selection.toString(hash);

                if (pw != null) {
                    pw.outputEvent("cipher", cipherDesc);
                }

            }
        } catch (Throwable t) {
            t.printStackTrace();
        }

        if (yourCiphers.size() > 2) {
            int best = yourCiphers.get(0).getCipherID();
            int worst = yourCiphers.get(yourCiphers.size() - 1).getCipherID();

            int choice;
            try {
                choice = choose(Arrays.asList(worst, best)).getCipherID();
            } catch (IOException e) {
                choice = worst;
                e.printStackTrace();
            }

            if (choice != worst) {
                pw.outputEvent("cipherpref", "{ \"cipherpref\": \"yes\" }");
            } else {
                pw.outputEvent("cipherpref", "{ \"cipherpref\": \"no\" }");
            }
        } else {
            pw.outputEvent("cipherpref", "{ \"cipherpref\": \"unknown\" }");
        }

        // TODO output was already made to the test output;
        // return chosen.toArray(new TestResultCipher[chosen.size()]);

        return new String[0];
    }

    public static class CertificateList {

        CertificateWrapper[] content;

        String[] hashes;

        public CertificateList(org.bouncycastle.asn1.x509.Certificate[] content) throws NoSuchAlgorithmException, IOException {
            this.content = new CertificateWrapper[content.length];
            hashes = new String[content.length];
            MessageDigest md = MessageDigest.getInstance(CertificateWrapper.HASH_TYPE);
            for (int i = content.length - 1; i >= 0; i--) {
                md.reset();
                if (i + 1 >= content.length) {
                    if (Arrays.equals(content[i].getIssuer().getEncoded(), content[i].getSubject().getEncoded())) {
                        this.content[i] = new CertificateWrapper(content[i]);
                    } else {
                        this.content[i] = new CertificateWrapper(content[i], null);
                    }
                } else {
                    this.content[i] = new CertificateWrapper(content[i], this.content[i + 1]);
                }
                hashes[i] = TruststoreUtil.outputFingerprint(content[i], md);
            }
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
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
            if ( !Arrays.equals(hashes, other.hashes))
                return false;
            return true;
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

        public String toString(int chainHash) {
            org.bouncycastle.crypto.tls.CipherConstants.CipherSuite cs = CipherConstants.getById(getCipherID());
            StringBuilder sb = new StringBuilder();
            Formatter f = new Formatter(sb);

            try {
                f.format(//
                        "{ " + //
                                "\"cipherid\": \"%06x\", \"ciphername\": \"%s\", " + //
                                "\"kextype\": \"%s\", \"kexsize\": {\"size\": %d%s}, " + //
                                "\"authtype\": \"%s\", \"authsize\": %d, " + //
                                "\"enctype\": \"%s\", \"encksize\": %d, \"encbsize\": %d, " + //
                                "\"mode\": \"%s\", " + //
                                "\"mactype\": \"%s\", \"macsize\": %d, " + //
                                "\"pfs\": \"%s\", " + //
                                "\"chain\": %d}", //
                        getCipherID(), JSONUtils.jsonEscape(getCipherName()), //
                        JSONUtils.jsonEscape(cs.getKex().getType()), info.getKexSize(), info.getKnownKexGroup() == null ? "" : ", \"name\":\"" + JSONUtils.jsonEscape(info.getKnownKexGroup()) + "\"", //
                        JSONUtils.jsonEscape(cs.getAuth().toString()), info.getAuthKeySize(), //
                        JSONUtils.jsonEscape(cs.getEnc().getType()), cs.getEnc().getKsize(), cs.getEnc().getBsize(), //
                        JSONUtils.jsonEscape(cs.getEnc().getCipherMode().toString()), //
                        JSONUtils.jsonEscape(cs.getMac().getType()), cs.getMac().getDgst(), //
                        cs.getKex().isPFS() ? "yes" : "no", chainHash);
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
        boolean brokenCipher = false;
        try {
            tcp.connect(tc);
            sock.getOutputStream().flush();
            tcp.close();
            sock.close();
        } catch (IOException e) {
        } catch (BrokenCipherException e) {
        }
        brokenCipher = tc.isBrokenCipher();

        int selectedCipherSuite = tc.getSelectedCipherSuite();
        if (selectedCipherSuite == 0) {
            return null;
        }

        if (tc.isFailed() || tcp.hasFailedLocaly()) {
            System.out.println("--- failed ---: " + cipherNames.get(selectedCipherSuite));
        }

        resultCipher.cipherID = selectedCipherSuite;
        resultCipher.priority = 0;
        resultCipher.supported = !tc.isBrokenCipher();
        if ( !brokenCipher) {
            resultCipher.kex = tc.getKeyExchange();
        } else {
            // So we know things are borked, let's try to recover as much as
            // possible ;-)
            if ( -1 != Arrays.binarySearch(new int[] {
                    0x00000B, 0x00000C, 0x00000D, 0x00000E, 0x00000F, 0x000010, 0x000017, 0x000018,
                    0x000019, 0x00001A, 0x00001B, 0x000030, 0x000031, 0x000034, 0x000036, 0x000037,
                    0x00003A, 0x00003E, 0x00003F, 0x000042, 0x000043, 0x000046, 0x000068, 0x000069,
                    0x00006C, 0x00006D, 0x000085, 0x000086, 0x000089, 0x000097, 0x000098, 0x00009B,
                    0x0000A0, 0x0000A1, 0x0000A4, 0x0000A5, 0x0000A6, 0x0000A7, 0x0000BB, 0x0000BC,
                    0x0000BF, 0x0000C1, 0x0000C2, 0x0000C5, 0x00C03E, 0x00C03F, 0x00C040, 0x00C041,
                    0x00C046, 0x00C047, 0x00C054, 0x00C055, 0x00C058, 0x00C059, 0x00C05A, 0x00C05B,
                    0x00C07E, 0x00C07F, 0x00C082, 0x00C083, 0x00C084, 0x00C085
            }, selectedCipherSuite)) {
                resultCipher.kex = new TlsDHKeyExchange(9, null, null);
            } else if ( -1 != Arrays.binarySearch(new int[] {
                    0x000011, 0x000012, 0x000013, 0x000014, 0x000015, 0x000016, 0x000032, 0x000033,
                    0x000038, 0x000039, 0x000040, 0x000044, 0x000045, 0x000067, 0x00006A, 0x00006B,
                    0x000087, 0x000088, 0x000099, 0x00009A, 0x00009E, 0x00009F, 0x0000A2, 0x0000A3,
                    0x0000BD, 0x0000BE, 0x0000C3, 0x0000C4, 0x00C042, 0x00C043, 0x00C044, 0x00C045,
                    0x00C052, 0x00C053, 0x00C056, 0x00C057, 0x00C07C, 0x00C07D, 0x00C080, 0x00C081,
                    0x00C09E, 0x00C09F, 0x00C0A2, 0x00C0A3
            }, selectedCipherSuite)) {
                resultCipher.kex = new TlsDHEKeyExchange(9, null, null);
            } else if ( -1 != Arrays.binarySearch(new int[] {
                    0x00C001, 0x00C002, 0x00C003, 0x00C004, 0x00C005, 0x00C00B, 0x00C00C, 0x00C00D,
                    0x00C00E, 0x00C00F, 0x00C015, 0x00C016, 0x00C017, 0x00C018, 0x00C019, 0x00C025,
                    0x00C026, 0x00C029, 0x00C02A, 0x00C02D, 0x00C02E, 0x00C031, 0x00C032, 0x00C04A,
                    0x00C04B, 0x00C04E, 0x00C04F, 0x00C05E, 0x00C05F, 0x00C062, 0x00C063, 0x00C074,
                    0x00C075, 0x00C078, 0x00C079, 0x00C088, 0x00C089, 0x00C08C, 0x00C08D
            }, selectedCipherSuite)) {
                resultCipher.kex = new TlsECDHKeyExchange(16, null, null, null, null);
            } else if ( -1 != Arrays.binarySearch(new int[] {
                    0x00C006, 0x00C007, 0x00C008, 0x00C009, 0x00C00A, 0x00C010, 0x00C011, 0x00C012,
                    0x00C013, 0x00C014, 0x00C023, 0x00C024, 0x00C027, 0x00C028, 0x00C02B, 0x00C02C,
                    0x00C02F, 0x00C030, 0x00C048, 0x00C049, 0x00C04C, 0x00C04D, 0x00C05C, 0x00C05D,
                    0x00C060, 0x00C061, 0x00C072, 0x00C073, 0x00C076, 0x00C077, 0x00C086, 0x00C087,
                    0x00C08A, 0x00C08B, 0x00C0AC, 0x00C0AD, 0x00C0AE, 0x00C0AF
            }, selectedCipherSuite)) {
                resultCipher.kex = new TlsECDHEKeyExchange(16, null, null, null, null);
            } else if ( -1 != Arrays.binarySearch(new int[] {
                    0x00002C, 0x00002D, 0x00002E, 0x00008A, 0x00008B, 0x00008C, 0x00008D, 0x00008E,
                    0x00008F, 0x000090, 0x000091, 0x000092, 0x000093, 0x000094, 0x000095, 0x0000A8,
                    0x0000A9, 0x0000AA, 0x0000AB, 0x0000AC, 0x0000AD, 0x0000AE, 0x0000AF, 0x0000B0,
                    0x0000B1, 0x0000B2, 0x0000B3, 0x0000B4, 0x0000B5, 0x0000B6, 0x0000B7, 0x0000B8,
                    0x0000B9, 0x00C033, 0x00C034, 0x00C035, 0x00C036, 0x00C037, 0x00C038, 0x00C039,
                    0x00C03A, 0x00C03B, 0x00C064, 0x00C065, 0x00C066, 0x00C067, 0x00C068, 0x00C069,
                    0x00C06A, 0x00C06B, 0x00C06C, 0x00C06D, 0x00C06E, 0x00C06F, 0x00C070, 0x00C071,
                    0x00C08E, 0x00C08F, 0x00C090, 0x00C091, 0x00C092, 0x00C093, 0x00C094, 0x00C095,
                    0x00C096, 0x00C097, 0x00C098, 0x00C099, 0x00C09A, 0x00C09B, 0x00C0A4, 0x00C0A5,
                    0x00C0A6, 0x00C0A7, 0x00C0A8, 0x00C0A9, 0x00C0AA, 0x00C0AB
            }, selectedCipherSuite)) {
                resultCipher.kex = new TlsPSKKeyExchange(24, null, null, null, null, null, null);
            } else if ( -1 != Arrays.binarySearch(new int[] {
                    0x00C01A, 0x00C01B, 0x00C01C, 0x00C01D, 0x00C01E, 0x00C01F, 0x00C020, 0x00C021,
                    0x00C022
            }, selectedCipherSuite)) {
                resultCipher.kex = new TlsSRPKeyExchange(21, null, null, null);
            } else {
                resultCipher.kex = null;
            }
        }
        resultCipher.compress = tc.getCompression();
        // resultCipher.cipher = tc.getCipher();
        resultCipher.info = tcp.getCipherInfo();

        return resultCipher;
    }

}
