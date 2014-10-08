package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;

public class BugTestingTLSClient extends TlsClientProtocol {

    private Bouncy bouncy;

    public BugTestingTLSClient(Bouncy bouncy, InputStream input, OutputStream output, SecureRandom secureRandom) {
        super(input, output, secureRandom);
        this.bouncy = bouncy;
    }

    boolean recievedHB = false;

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
        return recordStream.readRecord();
    }

    @Override
    protected void cleanupHandshake() {
        if (tlsSession != null) {
            SessionParameters sp = tlsSession.exportSessionParameters();
            try {
                Hashtable data = sp.readServerExtensions();
                this.bouncy.setExt(data);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
