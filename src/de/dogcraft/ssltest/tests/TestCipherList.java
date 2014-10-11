package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Vector;

import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.CompressionMethod;

import de.dogcraft.ssltest.utils.CipherProbingClient;

public class TestCipherList {

    private final String host;

    private final int port;

    private Vector<Integer> ciphers = new Vector<>();

    private boolean serverPref = false;

    private static HashMap<Integer, String> cipherNames = new HashMap<>();
    static {
        initCipherNames();
    }

    public TestCipherList(String host, int port) {
        this.host = host;
        this.port = port;
    }

    private static void initCipherNames() {
        Field[] fs = CipherSuite.class.getFields();
        for (Field field : fs) {
            try {
                cipherNames.put(field.getInt(null), field.getName());
            } catch (ReflectiveOperationException e) {
                e.printStackTrace();
            }
        }
    }

    public static Collection<Integer> getAllCiphers() {
        return cipherNames.keySet();
    }

    public Collection<Integer> getCiphers() {
        return ciphers;
    }

    public boolean hasServerPref() {
        return serverPref;
    }

    public String[] determineCiphers(TestOutput pw) throws IOException {
        LinkedList<Integer> yourCiphers = new LinkedList<>();
        Collection<Integer> ciphers = getAllCiphers();

        LinkedList<TestResultCipher> chosen = new LinkedList<>();
        try {
            for (int n = 0; n < ciphers.size(); n++) {
                int selection = choose(ciphers);
                yourCiphers.add(selection);

                TestResultCipher resultCipher = new TestResultCipher();
                resultCipher.cipherID = selection;
                resultCipher.priority = n;
                resultCipher.supported = true;

                String cipherDesc = cipherNames.get(selection) + " (0x" + Integer.toHexString(selection) + ") " + resultCipher.toString();

                if (pw != null) {
                    pw.output(cipherDesc);
                }

                chosen.add(resultCipher);

                ciphers.remove(selection);
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }
        int best = yourCiphers.get(0);
        int worst = yourCiphers.get(yourCiphers.size() - 1);
        int choice = choose(Arrays.asList(worst, best));
        serverPref = choice != worst;
        return chosen.toArray(new String[chosen.size()]);
    }

    public class TestResultCipher {

        public Integer cipherID;

        public Boolean supported;

        public Integer priority;

        public Integer getCipherID() {
            return cipherID;
        }

        public String getCipherName() {
            return TestCipherList.cipherNames.get(cipherID);
        }

        public Boolean getSupported() {
            return supported;
        }

        public Integer getPriority() {
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

    }

    private int choose(final Collection<Integer> ciphers) throws IOException {
        Socket sock = new Socket(host, port);
        TestingTLSClient tcp = new TestingTLSClient(sock.getInputStream(), sock.getOutputStream());
        CipherProbingClient tc = new CipherProbingClient(host, port, ciphers, new short[] { CompressionMethod._null });
        try {
            tcp.connect(tc);
            sock.getOutputStream().flush();
            tcp.close();
            sock.close();
        } catch (Throwable t) {

        }
        int selectedCipherSuite = tc.getSelectedCipherSuite();
        if (selectedCipherSuite == 0) {
            throw new IOException();
        }
        if (tc.isFailed() || tcp.hasFailedLocaly()) {
            System.out.println("--- failed ---: " + cipherNames.get(selectedCipherSuite));
        }
        return selectedCipherSuite;
    }

}
