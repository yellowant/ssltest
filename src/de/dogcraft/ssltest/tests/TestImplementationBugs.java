package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.net.Socket;
import java.util.Hashtable;
import java.util.LinkedList;

import org.bouncycastle.crypto.tls.BugTestingTLSClient;
import org.bouncycastle.crypto.tls.BugTestingTLSClient.CertificateObserver;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CompressionMethod;
import org.bouncycastle.crypto.tls.ContentType;
import org.bouncycastle.crypto.tls.HeartbeatMessage;
import org.bouncycastle.crypto.tls.HeartbeatMessageType;
import org.bouncycastle.crypto.tls.TlsFatalAlert;

import de.dogcraft.ssltest.utils.CipherProbingClient;
import de.dogcraft.ssltest.utils.CipherProbingClient.BrokenCipherException;

public class TestImplementationBugs {

    private Certificate cert;

    private final String host;

    private TestConnectionBuilder tcb;

    private LinkedList<Integer> illegalExtensions;

    protected class CompressionMethodEx extends CompressionMethod {

        public static final short LZS = 64;
    }

    public TestImplementationBugs(String host, TestConnectionBuilder tcb) {
        this.host = host;
        this.tcb = tcb;
    }

    @SuppressWarnings("deprecation")
    protected boolean testCompression(TestOutput pw, short compression) throws IOException {
        try (Socket sock = tcb.spawn()) {
            try (TestingTLSClient tcp = new TestingTLSClient(sock.getInputStream(), sock.getOutputStream())) {

                CipherProbingClient tc = new CipherProbingClient(host, TestCipherList.getAllCiphers(), new short[] {
                        compression, CompressionMethodEx.NULL
                }, null);

                boolean gotThrough = false;
                try {
                    tcp.connect(tc);
                    sock.getOutputStream().flush();

                    if (CompressionMethodEx.NULL != tc.getSelectedCompressionMethod()) {
                        gotThrough = true;
                    }
                } catch (BrokenCipherException t) {
                    System.out.println("Catched Broken cipher");
                    return true;
                } catch (Throwable t) {
                    return false;
                }

                return !(tcp.hasFailedLocaly() || tc.isFailed() || !gotThrough);
            } catch (BrokenCipherException t) {
                return false;
            }
        }
    }

    public boolean testCompressionDeflate(TestOutput pw) throws IOException {
        return testCompression(pw, CompressionMethodEx.DEFLATE);
    }

    public boolean testCompressionLZS(TestOutput pw) throws IOException {
        return testCompression(pw, CompressionMethodEx.LZS);
    }

    public String testHeartbeat() throws IOException {
        Socket sock = tcb.spawn();
        CertificateObserver observer = new CertificateObserver() {

            @Override
            public void onServerExtensionsReceived(Hashtable<Integer, byte[]> extensions) {
                TestImplementationBugs.this.extensions = extensions;
            }

            @Override
            public void onCertificateReceived(Certificate cert) {
                TestImplementationBugs.this.cert = cert;
            }

        };
        BugTestingTLSClient tcp = new BugTestingTLSClient(observer, sock.getInputStream(), sock.getOutputStream());
        CipherProbingClient tc = new CipherProbingClient(host, null, new short[] {
                CompressionMethod._null
        }, observer);
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
        String json = "{\"heartbeat\": \"" + (hb && resp ? "yes" : "no") + "\", ";
        json += "\"heartbleed\": \"" + (bleed && resp2 ? "yes" : "no") + "\"}";
        try {
            sock.getOutputStream().flush();
            tcp.close();
            sock.close();
        } catch (Throwable t) {

        }
        illegalExtensions = tc.getIllegalExtensions();
        return json;
    }

    private Hashtable<Integer, byte[]> extensions;

    private String cipherInfo;

    public org.bouncycastle.crypto.tls.Certificate getCert() {
        return cert;
    }

    public Hashtable<Integer, byte[]> getExt() {
        return extensions;
    }

    public void setCiperInfo(String cipherInfo) {
        this.cipherInfo = cipherInfo;
    }

    public String getHost() {
        return host;
    }

    public String getCipherInfo() {
        return cipherInfo;
    }

    public LinkedList<Integer> getIllegalExtensions() {
        return illegalExtensions;
    }

    public String testChangeCipherSpec() throws IOException {
        Socket sock = tcb.spawn();
        CertificateObserver observer = new CertificateObserver() {

            @Override
            public void onServerExtensionsReceived(Hashtable<Integer, byte[]> extensions) {
                TestImplementationBugs.this.extensions = extensions;
            }

            @Override
            public void onCertificateReceived(Certificate cert) {
                TestImplementationBugs.this.cert = cert;
            }

        };
        BugTestingTLSClient tcp = new BugTestingTLSClient(observer, sock.getInputStream(), sock.getOutputStream());
        CipherProbingClient tc = new CipherProbingClient(host, null, new short[] {
                CompressionMethod._null
        }, observer);
        tcp.connect(tc);
        sock.setSoTimeout(1500);

        //Send message once
        try {
            tcp.sendMessage(ContentType.change_cipher_spec, new byte[] {
                0x01
            });
        } catch (IOException e) {
            return "{\"accepted\":\"no\"}";
        }

        // Second instance triggers different protocol errors depending on whether the server is vulnerable
        try {
            tcp.sendMessage(ContentType.change_cipher_spec, new byte[] {
                0x01
            });
        } catch (TlsFatalAlert e) {
            if(10 == e.getAlertDescription()) {
                return "{\"accepted\":\"no\"}";
            } else {
                return "{\"accepted\":\"yes\"}";
            }
        } catch (IOException e) {
            return "{\"accepted\":\"no\"}";
        }

        return "{\"accepted\":\"yes\"}";
    }

}
