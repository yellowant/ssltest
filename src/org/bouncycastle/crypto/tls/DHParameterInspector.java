package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class DHParameterInspector {

    public static int inspectDH(TlsDHKeyExchange ex) {
        DHParameters params = ex.dhAgreeClientPrivateKey.getParameters();
        if (ex instanceof TlsDHEKeyExchange) {
            TlsSignerCredentials ephermal = ((TlsDHEKeyExchange) ex).serverCredentials;
            analyzeEphermal(ephermal);
        }
        int len = params.getP().bitLength();
        return len;
    }

    public static int inspectECDH(TlsECDHKeyExchange ex) {
        ECDomainParameters params = ex.ecAgreePrivateKey.getParameters();
        if (ex instanceof TlsECDHEKeyExchange) {
            TlsSignerCredentials ephermal = ((TlsECDHEKeyExchange) ex).serverCredentials;
            analyzeEphermal(ephermal);
        }
        return params.getN().bitLength();
    }

    private static void analyzeEphermal(TlsSignerCredentials ephermal) {
        if (ephermal == null) {
            return;
        }

        Certificate c = ephermal.getCertificate();
        System.out.println(c);
        System.out.println(ephermal.getSignatureAndHashAlgorithm());
    }

    public static int inspectRSA(TlsRSAKeyExchange ex) {
        RSAKeyParameters params = ex.rsaServerPublicKey;
        return params.getModulus().bitLength();
    }

    public static String inspectRSAPublicExp(TlsRSAKeyExchange ex) {
        RSAKeyParameters params = ex.rsaServerPublicKey;
        return params.getModulus().bitLength() + " (" + params.getExponent() + ")";
    }

}
