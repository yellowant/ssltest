package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

import de.dogcraft.ssltest.tests.TestingTLSClient.TLSCipherInfo;

public class CipherPublisher {

    public static void publish(TlsCipher c, TLSCipherInfo info) {
        if (c instanceof TlsAEADCipher) {
            AEADBlockCipher ci = ((TlsAEADCipher) c).encryptCipher;
            if (ci instanceof CCMBlockCipher) {
                info.setMac("CCM", 0);
            } else if (ci instanceof GCMBlockCipher) {
                info.setMac("GCM", 0);
            } else {
                info.setMac("???", 0);
            }
            info.setCipher(ci.getAlgorithmName(), ci.getUnderlyingCipher().getBlockSize());
        } else if (c instanceof TlsBlockCipher) {
            TlsMac mac = ((TlsBlockCipher) c).readMac;
            info.setMac(mac.mac.getAlgorithmName(), mac.mac.getMacSize());

            BlockCipher cipher = ((TlsBlockCipher) c).encryptCipher;
            info.setCipher(cipher.getAlgorithmName(), cipher.getBlockSize());
        } else if (c instanceof TlsStreamCipher) {
            TlsMac mac = ((TlsStreamCipher) c).readMac;
            info.setMac(mac.mac.getAlgorithmName(), mac.mac.getMacSize());

            StreamCipher cipher = ((TlsStreamCipher) c).encryptCipher;
            info.setCipher(cipher.getAlgorithmName(), 0);
        } else if (c instanceof Chacha20Poly1305) {
            info.setCipher("Chacha20", 0);
            info.setMac("Poly1305", 16);
        }
    }
}
