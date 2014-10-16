package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.crypto.tls.DHParameterInspector;
import org.bouncycastle.crypto.tls.SessionParameters;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsRSAKeyExchange;

public class TestingTLSClient extends TlsClientProtocol {

    private static SecureRandom random = new SecureRandom();

    private Hashtable<Integer, byte[]> extensions;

    private TLSCipherInfo cipherInfo;

    private boolean failedLocaly;

    public TestingTLSClient(InputStream input, OutputStream output) {
        super(input, output, random);
        extensions = null;
        cipherInfo = null;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void cleanupHandshake() {
        if (tlsSession != null) {
            SessionParameters sp = tlsSession.exportSessionParameters();
            try {
                extensions = sp.readServerExtensions();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        cipherInfo = new TLSCipherInfo();
        cipherInfo.raw = keyExchange;
        if (keyExchange instanceof TlsDHKeyExchange) {
            cipherInfo.kexType = "DH";
            cipherInfo.kexSize = DHParameterInspector.inspectDH((TlsDHKeyExchange) keyExchange);
        } else if (keyExchange instanceof TlsECDHKeyExchange) {
            cipherInfo.kexType = "ECDH";
            cipherInfo.kexSize = DHParameterInspector.inspectECDH((TlsECDHKeyExchange) keyExchange);
        } else if (keyExchange instanceof TlsRSAKeyExchange) {
            cipherInfo.kexType = "RSA";
            cipherInfo.kexSize = DHParameterInspector.inspectRSA((TlsRSAKeyExchange) keyExchange);
            cipherInfo.authKeyType = "RSA";
            cipherInfo.authKeySize = cipherInfo.kexSize;
            // } else if (keyExchange instanceof TlsPSKKeyExchange) {
            // cipherInfo.kexType = "PSK";
            // cipherInfo.kexSize =
            // DHParameterInspector.inspectPSK((TlsPSKKeyExchange) keyExchange);
            // } else if (keyExchange instanceof TlsSRPKeyExchange) {
            // cipherInfo.kexType = "SRP";
            // cipherInfo.kexSize =
            // DHParameterInspector.inspectSRP((TlsSRPKeyExchange) keyExchange);
        } else {
            cipherInfo.kexType = "Unknown";
            cipherInfo.kexSize = 0;
        }

        super.cleanupHandshake();
    }

    @Override
    protected void raiseAlert(short alertLevel, short alertDescription, String message, Exception cause) throws IOException {
        if (cause != null) {
            failedLocaly = true;
            cause.printStackTrace();
        }
        super.raiseAlert(alertLevel, alertDescription, message, cause);
    }

    public boolean hasFailedLocaly() {
        return failedLocaly;
    }

    protected Hashtable<Integer, byte[]> getExtensions() {
        return extensions;
    }

    public class TLSCipherInfo {

        /** Key Exchange format: DH, DHE, ECDH, ECDHE, RSA, CK, PSK, SRP, NULL */
        private String kexType;

        /** Key Exchange key size */
        private Integer kexSize;

        /** Authentication Key Format: RSA, DSA, ECDSA */
        private String authKeyType;

        /** Authentication Key Size */
        private int authKeySize;

        /** Raw information on this particular Key Exchange */
        private TlsKeyExchange raw;

        public String getKexType() {
            return kexType;
        }

        public Integer getKexSize() {
            return kexSize;
        }

        public String getAuthKeyType() {
            return authKeyType;
        }

        public int getAuthKeySize() {
            return authKeySize;
        }

        public TlsKeyExchange getRaw() {
            return raw;
        }

        public String getCipherType() {
            return "FOO";
        }

        public int getCipherSize() {
            return 42;
        }

    }

    public TLSCipherInfo getCipherInfo() {
        return cipherInfo;
    }

}
