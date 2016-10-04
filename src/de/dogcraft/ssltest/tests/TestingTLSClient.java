package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.crypto.tls.CipherPublisher;
import org.bouncycastle.crypto.tls.DHParameterInspector;
import org.bouncycastle.crypto.tls.DHParameterInspector.KexInfo;
import org.bouncycastle.crypto.tls.SessionParameters;
import org.bouncycastle.crypto.tls.TlsCipher;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsRSAKeyExchange;

import de.dogcraft.ssltest.utils.CipherProbingClient;

public class TestingTLSClient extends TlsClientProtocol implements AutoCloseable {

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
        TlsCipher c;
        try {
            c = getPeer().getCipher();
            CipherPublisher.publish(c, cipherInfo);
        } catch (IOException e) {
        }
        cipherInfo.raw = keyExchange;
        cipherInfo.pfs = false;
        if (keyExchange instanceof TlsDHKeyExchange) {
            cipherInfo.kexType = "DH";
            cipherInfo.accept(DHParameterInspector.inspectDH((TlsDHKeyExchange) keyExchange, cipherInfo));
            cipherInfo.pfs = keyExchange instanceof TlsDHEKeyExchange;
        } else if (keyExchange instanceof TlsECDHKeyExchange) {
            cipherInfo.kexType = "ECDH";
            cipherInfo.accept(DHParameterInspector.inspectECDH((TlsECDHKeyExchange) keyExchange));
            cipherInfo.pfs = keyExchange instanceof TlsECDHEKeyExchange;
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
            // cipherInfo.pfs = true;
        } else {
            cipherInfo.kexType = "Unknown";
            cipherInfo.kexSize = -1;
        }

        super.cleanupHandshake();
    }

    @Override
    protected void raiseAlert(short alertLevel, short alertDescription, String message, Exception cause) throws IOException {
        if (cause != null) {
            failedLocaly = true;
            if ( !(cause instanceof CipherProbingClient.BrokenCipherException)) {
                cause.printStackTrace();
            }
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

        private boolean pfs;

        /** Key Exchange format: DH, ECDH, RSA, CK, PSK, SRP, NULL */
        private String kexType;

        private String knownKexGroup;

        /** Key Exchange key size */
        private int kexSize = -1;

        /** Authentication Key Format: RSA, DSA, ECDSA */
        private String authKeyType;

        /** Authentication Key Size */
        private int authKeySize = -1;

        /** Raw information on this particular Key Exchange */
        private TlsKeyExchange raw;

        private String cipherName = "";

        private int cipherBSize;

        private int cipherKSize;

        private String macType;

        private int macSize;

        public boolean isPFS() {
            return pfs;
        }

        private void accept(KexInfo ki) {
            authKeyType = ki.auth;
            authKeySize = ki.authSize;
            kexSize = ki.size;
            knownKexGroup = ki.authName;
        }

        public String getKnownKexGroup() {
            return knownKexGroup;
        }

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
            return cipherName.split("/", 2)[0];
        }

        public String getCipherMode() {
            String[] split = cipherName.split("/", 2);
            if (split.length < 2)
                return null;
            return split[1];
        }

        public int getCipherBSize() {
            return cipherBSize;
        }

        public int getCipherKSize() {
            return cipherKSize;
        }

        public String getMacType() {
            return macType;
        }

        public int getMacSize() {
            return macSize;
        }

        public void setMac(String algorithmName, int macLen) {
            macType = algorithmName;
            macSize = macLen * 8;
        }

        public void setCipher(String algorithmName, int blockSize, int keySize) {
            cipherName = algorithmName;
            cipherBSize = blockSize * 8;
            cipherKSize = keySize * 8;
        }

    }

    public TLSCipherInfo getCipherInfo() {
        return cipherInfo;
    }

}
