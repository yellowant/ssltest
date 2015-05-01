package org.bouncycastle.crypto.tls;

import java.lang.reflect.Field;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
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
                info.setMac("GCM", ((GCMBlockCipher) ci).getOutputSize(0));
            } else {
                info.setMac("???", 0);
            }
            int keySize = readKeySize(ci.getUnderlyingCipher());
            info.setCipher(ci.getAlgorithmName(), ci.getUnderlyingCipher().getBlockSize(), keySize);
        } else if (c instanceof TlsBlockCipher) {
            TlsMac mac = ((TlsBlockCipher) c).readMac;
            info.setMac(mac.mac.getAlgorithmName(), mac.mac.getMacSize());

            BlockCipher cipher = ((TlsBlockCipher) c).encryptCipher;
            int keySize = readKeySize(cipher);
            info.setCipher(cipher.getAlgorithmName(), cipher.getBlockSize(), keySize);
        } else if (c instanceof TlsStreamCipher) {
            TlsMac mac = ((TlsStreamCipher) c).readMac;
            info.setMac(mac.mac.getAlgorithmName(), mac.mac.getMacSize());

            StreamCipher cipher = ((TlsStreamCipher) c).encryptCipher;
            int keySize = readKeySize(cipher);
            info.setCipher(cipher.getAlgorithmName(), 0, keySize);
        } else if (c instanceof Chacha20Poly1305) {
            info.setCipher("Chacha20", 0, 32);
            info.setMac("Poly1305", 16);
        }
    }

    private static int readKeySize(BlockCipher cipher) {
        try {
            if (cipher instanceof CBCBlockCipher) {
                Field cipher_field = CBCBlockCipher.class.getDeclaredField("cipher");
                cipher_field.setAccessible(true);
                Object raw_cipher = cipher_field.get(cipher);

                if (raw_cipher instanceof BlockCipher) {
                    return readKeySize((BlockCipher) raw_cipher);
                } else {
                    System.out.println(raw_cipher.getClass().getCanonicalName());
                }
            } else if (cipher instanceof CamelliaEngine) {
                CamelliaEngine e = (CamelliaEngine) cipher;
                Field e_f = CamelliaEngine.class.getDeclaredField("_keyIs128");
                e_f.setAccessible(true);
                boolean b = e_f.getBoolean(e);
                return b ? 16 : 32;
            } else if (cipher instanceof AESEngine) {
                AESEngine e = (AESEngine) cipher;
                Field e_f = AESEngine.class.getDeclaredField("ROUNDS");
                e_f.setAccessible(true);
                int value = e_f.getInt(e);

                return 4 * (value - 6);
            } else if (cipher instanceof DESedeEngine) {
                return 14;
            } else if (cipher instanceof DESEngine) {
                return 7;
            } else {
                System.out.println(cipher.getClass().getCanonicalName());
            }
        } catch (Exception e) {
            return 0;
        }

        return cipher.getBlockSize();
    }

    private static int readKeySize(StreamCipher cipher) {
        try {
            if (cipher instanceof RC4Engine) {
                RC4Engine e = (RC4Engine) cipher;
                Field e_f = RC4Engine.class.getDeclaredField("workingKey");
                e_f.setAccessible(true);
                byte[] value = (byte[]) e_f.get(e);
                return value.length;
            }
        } catch (Exception e) {
            return 0;
        }

        return 0;
    }
}
