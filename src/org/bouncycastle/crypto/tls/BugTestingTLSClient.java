package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.Hashtable;

public class BugTestingTLSClient extends TlsClientProtocol {

    private static SecureRandom random = new SecureRandom();

    private CertificateObserver certObserver;

    public BugTestingTLSClient(CertificateObserver certObserver, InputStream input, OutputStream output) {
        super(input, output, random);
        this.certObserver = certObserver;
    }

    private boolean recievedHB = false;

    public boolean fetchRecievedHB() {
        boolean hb = recievedHB;
        recievedHB = false;
        return hb;
    }

    @Override
    protected void processRecord(short protocol, byte[] buf, int offset, int len) throws IOException {
        if (protocol == ContentType.heartbeat) {
            recievedHB = true;
        }
        super.processRecord(protocol, buf, offset, len);
    }

    public boolean sendHeartbeat(HeartbeatMessage hb, boolean bleed) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        hb.encode(getContext(), baos);
        byte[] pla = baos.toByteArray();
        if (bleed) {
            pla[2] += 32;

        }
        safeWriteRecord(ContentType.heartbeat, pla, 0, pla.length);
        try {
            while (recordStream.readRecord()) {

            }
            return false;
        } catch (SocketTimeoutException e) {
            // is ok
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void cleanupHandshake() {
        if (tlsSession != null) {
            SessionParameters sp = tlsSession.exportSessionParameters();
            try {
                this.certObserver.onServerExtensionsReceived(sp.readServerExtensions());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public interface CertificateObserver {

        public void onServerExtensionsReceived(Hashtable<Integer, byte[]> extensions);

        public void onCertificateReceived(Certificate cert);

    }

}
