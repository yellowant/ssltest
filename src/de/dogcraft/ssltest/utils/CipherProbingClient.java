package de.dogcraft.ssltest.utils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.HeartbeatExtension;
import org.bouncycastle.crypto.tls.HeartbeatMode;
import org.bouncycastle.crypto.tls.NameType;
import org.bouncycastle.crypto.tls.ServerName;
import org.bouncycastle.crypto.tls.ServerNameList;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;

public class CipherProbingClient extends DefaultTlsClient {

    private static SecureRandom random = new SecureRandom();

    private Certificate cert;

    private final String host;

    private final int port;

    private final int[] ciphers;

    private final short[] comp;

    public CipherProbingClient(String host, int port, Collection<Integer> ciphers, short[] comp) {
        this.host = host;
        this.port = port;

        Integer[] tmpI = (Integer[]) ciphers.toArray();
        int[] tmp = new int[tmpI.length];
        for (int idx = 0; idx < tmpI.length; idx++) {
            tmp[idx] = tmpI[idx];
        }
        this.ciphers = tmp;

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
