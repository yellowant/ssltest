package de.dogcraft.ssltest.utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.BugTestingTLSClient.CertificateObserver;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.HeartbeatExtension;
import org.bouncycastle.crypto.tls.HeartbeatMode;
import org.bouncycastle.crypto.tls.NameType;
import org.bouncycastle.crypto.tls.ServerName;
import org.bouncycastle.crypto.tls.ServerNameList;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsKeyExchange;

import de.dogcraft.ssltest.tests.TestCipherList;

public class CipherProbingClient extends DefaultTlsClient {

    public static class BrokenCipherException extends RuntimeException {

    }

    private final String host;

    private final int[] ciphers;

    private final short[] comp;

    CertificateObserver observer;

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
            if (s.startsWith("TLS_RSA_EXPORT_") || s.startsWith("TLS_DH_anon_") || s.startsWith("TLS_ECDH_anon_") || s.startsWith("TLS_PSK_") || s.startsWith("TLS_SRP_")) {
                brokenCipher = true;
                throw new BrokenCipherException();
            }
            throw t;
        }
    }

    @Override
    public int[] getCipherSuites() {
        if (ciphers == null) {
            return new int[] {
                    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
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

}
