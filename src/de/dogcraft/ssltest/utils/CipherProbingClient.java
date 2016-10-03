package de.dogcraft.ssltest.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Vector;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.BugTestingTLSClient.CertificateObserver;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.EncryptionAlgorithm;
import org.bouncycastle.crypto.tls.HeartbeatExtension;
import org.bouncycastle.crypto.tls.HeartbeatMode;
import org.bouncycastle.crypto.tls.MACAlgorithm;
import org.bouncycastle.crypto.tls.NameType;
import org.bouncycastle.crypto.tls.ServerName;
import org.bouncycastle.crypto.tls.ServerNameList;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCipher;
import org.bouncycastle.crypto.tls.TlsCompression;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsUtils;

import de.dogcraft.ssltest.tests.TestCipherList;

public class CipherProbingClient extends DefaultTlsClient {

    public static class BrokenCipherException extends RuntimeException {

    }

    private final String host;

    private final int[] ciphers;

    private final short[] comp;

    CertificateObserver observer;

    LinkedList<Integer> illegalExtensions = null;

    public CipherProbingClient(String host, Collection<Integer> ciphers, short[] comp, CertificateObserver observer) {
        this.host = host;
        this.observer = observer;
        if (ciphers != null) {
            Integer[] tmpI = ciphers.toArray(new Integer[ciphers.size()]);
            int[] tmp = new int[tmpI.length];
            for (int idx = 0; idx < tmpI.length; idx++) {
                tmp[idx] = tmpI[idx];
            }
            this.ciphers = tmp;
        } else {
            this.ciphers = null;
        }

        this.comp = comp;
    }

    boolean brokenCipher = false;

    @Override
    public TlsKeyExchange getKeyExchange() throws IOException {
        try {
            return super.getKeyExchange();
        } catch (TlsFatalAlert t) {
            String s = TestCipherList.resolveCipher(selectedCipherSuite);
            switch (selectedCipherSuite) {
            case CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA:
                return createRSAKeyExchange();
            }
            if (s.startsWith("TLS_RSA_EXPORT_") // export
                    || s.startsWith("TLS_RSA_WITH_DES_") || s.startsWith("TLS_DHE_RSA_WITH_DES_") // _DES_
                    || s.startsWith("TLS_PSK_") || s.startsWith("TLS_DHE_PSK_WITH_") || s.startsWith("TLS_RSA_PSK_WITH_") // PSK
                    || s.startsWith("TLS_DH_anon_") || s.startsWith("TLS_ECDH_anon_") // DH_anon
                    || s.startsWith("TLS_SRP_")) {
                brokenCipher = true;
                throw new BrokenCipherException();
            }
            System.out.println(s);
            throw t;
        }
    }

    @Override
    public TlsCipher getCipher() throws IOException {
        try {
            return super.getCipher();
        } catch (TlsFatalAlert e) {
            switch (selectedCipherSuite) {
            case CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm.IDEA_CBC, MACAlgorithm.hmac_sha1);
            }
            if (selectedCipherSuite != 0) {
                System.err.println(TestCipherList.resolveCipher(selectedCipherSuite));
                e.printStackTrace();
            }
            throw e;
        }
    }

    @Override
    public TlsCompression getCompression() throws IOException {
        try {
            return super.getCompression();
        } catch (TlsFatalAlert e) {
            return new TlsCompression() {

                @Override
                public OutputStream decompress(OutputStream output) {
                    throw new BrokenCipherException();
                }

                @Override
                public OutputStream compress(OutputStream output) {
                    throw new BrokenCipherException();
                }
            };
        }
    }

    @Override
    public int[] getCipherSuites() {
        if (ciphers == null) {
            return new int[] {
                    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, //
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, //
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,//
                    CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            };
        }
        return ciphers;
    }

    @Override
    public short[] getCompressionMethods() {
        return comp;
    }

    @Override
    public Hashtable<Integer, byte[]> getClientExtensions() throws IOException {
        @SuppressWarnings("unchecked")
        Hashtable<Integer, byte[]> clientExtensions = super.getClientExtensions();

        TlsExtensionsUtils.addServerNameExtension(clientExtensions, new ServerNameList(new Vector<>(Arrays.asList(new ServerName(NameType.host_name, host)))));
        TlsExtensionsUtils.addHeartbeatExtension(clientExtensions, new HeartbeatExtension(HeartbeatMode.peer_allowed_to_send));

        return clientExtensions;
    }

    @Override
    public TlsAuthentication getAuthentication() throws IOException {
        return new ServerOnlyTlsAuthentication() {

            @Override
            public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {
                if (observer != null) {
                    observer.onCertificateReceived(serverCertificate);
                }
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

    public boolean isBrokenCipher() {
        return brokenCipher;
    }

    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
        if (secureRenegotiation)
            return;
        // TODO : interesting... broken? what?
        System.err.println("Something might be broken (see " + CipherProbingClient.class.getName() + ".notifySecureRenegotiation");
    }

    @Override
    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        LinkedList<Integer> illegalExt = new LinkedList<>();
        try {
            /*
             * TlsProtocol implementation validates that any server extensions
             * received correspond to client extensions sent. By default, we
             * don't send any, and this method is not called.
             */
            if (serverExtensions != null) {
                this.serverECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(serverExtensions);
                if (this.serverECPointFormats != null && !TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite)) {
                    illegalExt.add(TlsECCUtils.EXT_ec_point_formats);
                }

                /*
                 * RFC 5246 7.4.1.4.1. Servers MUST NOT send this extension.
                 */
                if (serverExtensions.containsKey(TlsUtils.EXT_signature_algorithms)) {
                    illegalExt.add(TlsUtils.EXT_signature_algorithms);
                }

                int[] namedCurves = TlsECCUtils.getSupportedEllipticCurvesExtension(serverExtensions);
                if (namedCurves != null) {
                    illegalExt.add(TlsECCUtils.EXT_elliptic_curves);
                }
                if (illegalExt.size() > 0) {
                    illegalExtensions = illegalExt;
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        } catch (TlsFatalAlert a) {
        }
    }

    public LinkedList<Integer> getIllegalExtensions() {
        return illegalExtensions;
    }

    public short getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

}
