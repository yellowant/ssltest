package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;

public class TestingTLSClient extends TlsClientProtocol {

    private final Bouncy bouncy;

    public TestingTLSClient(Bouncy bouncy, InputStream input, OutputStream output, SecureRandom secureRandom) {
        super(input, output, secureRandom);
        this.bouncy = bouncy;
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

        String cipherInfo = "";
        if (keyExchange instanceof TlsDHKeyExchange) {
            int bitLength = DHParameterInspector.inspectDH((TlsDHKeyExchange) keyExchange);
            cipherInfo = "DH: " + bitLength;
        } else if (keyExchange instanceof TlsECDHKeyExchange) {
            TlsECDHKeyExchange teke = (TlsECDHKeyExchange) keyExchange;
            cipherInfo = "ECDH: " + DHParameterInspector.inspectECDH(teke);
        } else if (keyExchange instanceof TlsRSAKeyExchange) {
            cipherInfo = "RSA: " + DHParameterInspector.inspectRSA((TlsRSAKeyExchange) keyExchange);
        }

        bouncy.setCiperInfo(cipherInfo);

        super.cleanupHandshake();
    }

}
