package de.dogcraft.ssltest;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Vector;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.BugTestingTLSClient;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.CompressionMethod;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.crypto.tls.HeartbeatExtension;
import org.bouncycastle.crypto.tls.HeartbeatMessage;
import org.bouncycastle.crypto.tls.HeartbeatMessageType;
import org.bouncycastle.crypto.tls.HeartbeatMode;
import org.bouncycastle.crypto.tls.NameType;
import org.bouncycastle.crypto.tls.ServerName;
import org.bouncycastle.crypto.tls.ServerNameList;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;

import de.dogcraft.ssltest.output.PrintstreamTestOutput;
import de.dogcraft.ssltest.tests.TestOutput;
import de.dogcraft.ssltest.tests.TestingTLSClient;

public class Bouncy {

    org.bouncycastle.crypto.tls.Certificate cert;

    String host;

    int port;

    public Bouncy(String host, int port) {
        this.host = host;
        this.port = port;
    }

    private final class CipherProbingClient extends DefaultTlsClient {

        private final int[] ciphers;

        private final short[] comp;

        private CipherProbingClient(int[] ciphers, short[] comp) {
            this.ciphers = ciphers;
            this.comp = comp;

        }

        @Override
        public int[] getCipherSuites() {
            return ciphers;
        }

        @Override
        public short[] getCompressionMethods() {
            return comp;
        }

        @Override
        public Hashtable getClientExtensions() throws IOException {
            Hashtable clientExtensions = super.getClientExtensions();
            TlsExtensionsUtils.addServerNameExtension(clientExtensions, new ServerNameList(new Vector<>(Arrays.asList(new ServerName(NameType.host_name, host)))));
            TlsExtensionsUtils.addHeartbeatExtension(clientExtensions, new HeartbeatExtension(HeartbeatMode.peer_allowed_to_send));
            return clientExtensions;
        }

        @Override
        public TlsAuthentication getAuthentication() throws IOException {
            return new ServerOnlyTlsAuthentication() {

                @Override
                public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {
                    cert = serverCertificate;
                }
            };
        }

        boolean failed = false;

        @Override
        public void notifyAlertReceived(short alertLevel, short alertDescription) {
            if (alertLevel == AlertLevel.fatal && AlertDescription.handshake_failure == alertDescription) {
                failed = true;
            }
            super.notifyAlertReceived(alertLevel, alertDescription);
        }

        public boolean isFailed() {
            return failed;
        }

        public int getSelectedCipherSuite() {
            return selectedCipherSuite;
        }

    }

    SecureRandom sr = new SecureRandom();

    public static void main(String[] args) throws IOException {
        TestOutput to = new PrintstreamTestOutput(System.out);
        Bouncy b = new Bouncy("www.openssl.org", 443);
        String[] ciph = b.determineCiphers(to);
        for (String string : ciph) {
            System.out.println(string);
        }
        if (b.hasServerPref()) {
            System.out.println("Server prefers.");
        } else {
            System.out.println("Server doesn't care.");
        }
        Certificate[] c = b.cert.getCertificateList();
        for (Certificate c1 : c) {
            System.out.println("i: " + c1.getIssuer().toString());
            System.out.println(c1.getSubject().toString());
        }

        byte[] sn = (byte[]) b.ext.get(ExtensionType.server_name);
        byte[] hb = (byte[]) b.ext.get(ExtensionType.heartbeat);
        byte[] rn = (byte[]) b.ext.get(ExtensionType.renegotiation_info);
        System.out.println("renego: " + (rn == null ? "off" : "on"));
        System.out.println("heartbeat: " + (hb == null ? "off" : "on"));
        b.testBug(to);

    }

    static HashMap<Integer, String> cipherNames = new HashMap<>();
    static {
        getCiphers();
    }

    private static void getCiphers() {
        Field[] fs = CipherSuite.class.getFields();
        for (Field field : fs) {
            try {
                cipherNames.put(field.getInt(null), field.getName());
            } catch (ReflectiveOperationException e) {
                e.printStackTrace();
            }
        }
    }

    LinkedList<Integer> ciphers = new LinkedList<>();

    public String[] determineCiphers(TestOutput pw) throws IOException {
        LinkedList<Integer> yourCiphers = new LinkedList<>();
        int[] ciphers = getAllCiphers();
        LinkedList<String> chosen = new LinkedList<>();
        try {
            for (int n = 0; n < 80; n++) {
                int selection = choose(ciphers, sr);
                yourCiphers.add(selection);
                String cipherDesc = cipherNames.get(selection) + " (0x" + Integer.toHexString(selection) + ") " + cipherInfo;
                if (pw != null) {
                    pw.output(cipherDesc);
                }
                chosen.add(cipherDesc);
                int[] ciphers2 = new int[ciphers.length - 1];
                int j = 0;
                for (int i = 0; i < ciphers.length; i++) {
                    if (ciphers[i] != selection) {
                        ciphers2[j++] = ciphers[i];
                    }
                }
                ciphers = ciphers2;
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }
        int best = yourCiphers.get(0);
        int worst = yourCiphers.get(yourCiphers.size() - 1);
        int choice = choose(new int[] {
                worst, best
        }, sr);
        serverPref = choice != worst;
        return chosen.toArray(new String[chosen.size()]);
    }

    public boolean testDeflate(TestOutput pw) throws IOException {
        Socket sock = new Socket(host, port);
        TestingTLSClient tcp = new TestingTLSClient(this, sock.getInputStream(), sock.getOutputStream(), sr);
        CipherProbingClient tc = new CipherProbingClient(getAllCiphers(), new short[] {
            CompressionMethod.DEFLATE
        });
        try {
            tcp.connect(tc);
            sock.getOutputStream().flush();
            tcp.close();
            sock.close();
        } catch (Throwable t) {

        }
        return tcp.isFailedLocaly() || tc.isFailed();
    }

    boolean serverPref = false;

    public boolean hasServerPref() {
        return serverPref;
    }

    public void testBug(TestOutput pw) throws IOException {
        Socket sock = new Socket(host, port);
        BugTestingTLSClient tcp = new BugTestingTLSClient(this, sock.getInputStream(), sock.getOutputStream(), sr);
        CipherProbingClient tc = new CipherProbingClient(getAllCiphers(), new short[] {
            CompressionMethod._null
        });
        tcp.connect(tc);
        HeartbeatMessage hbm = new HeartbeatMessage(HeartbeatMessageType.heartbeat_request, new byte[] {
                1, 2, 3, 4, 5, 6, 7, 8
        }, 16);
        sock.setSoTimeout(1500);
        boolean hb = false;
        try {
            hb = tcp.sendHeartbeat(hbm, false);
        } catch (IOException e) {
        }
        boolean resp = tcp.fetchRecievedHB();
        boolean bleed = false;
        try {
            bleed = tcp.sendHeartbeat(hbm, true);
        } catch (IOException e) {
        }
        boolean resp2 = tcp.fetchRecievedHB();

        if (hb && resp) {
            pw.output("heartbeat works");
        } else {
            pw.output("heartbeat works not");
        }
        if (bleed && resp2) {
            pw.output("heartbleed works!!!");
        } else {
            pw.output("heartbleed works not");
        }
        try {
            sock.getOutputStream().flush();
            tcp.close();
            sock.close();
        } catch (Throwable t) {

        }

    }

    Hashtable ext;

    private String cipherInfo;

    private int choose(final int[] ciphers, SecureRandom sr) throws IOException {
        Socket sock = new Socket(host, port);
        TestingTLSClient tcp = new TestingTLSClient(this, sock.getInputStream(), sock.getOutputStream(), sr);
        CipherProbingClient tc = new CipherProbingClient(ciphers, new short[] {
            CompressionMethod._null
        });
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
        if (tc.isFailed() || tcp.isFailedLocaly()) {
            System.out.println("--- failed ---: " + cipherNames.get(selectedCipherSuite));
        }
        return selectedCipherSuite;
    }

    private int[] getAllCiphers() {
        Field[] fs = CipherSuite.class.getFields();
        int[] data = new int[fs.length];
        int pos = 0;
        for (int i = 0; i < data.length; i++) {
            try {
                int int1 = fs[i].getInt(null);
                data[pos++] = int1;
            } catch (ReflectiveOperationException e) {
                e.printStackTrace();
            }
        }
        return data;
    }

    public void setExt(Hashtable data) {
        ext = data;
    }

    public org.bouncycastle.crypto.tls.Certificate getCert() {
        return cert;
    }

    public Hashtable getExt() {
        return ext;
    }

    public void setCiperInfo(String cipherInfo) {
        this.cipherInfo = cipherInfo;
    }

}
