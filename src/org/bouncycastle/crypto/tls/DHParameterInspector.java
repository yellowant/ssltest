package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import de.dogcraft.ssltest.KnownDHGroup;
import de.dogcraft.ssltest.tests.TestingTLSClient.TLSCipherInfo;

public class DHParameterInspector {

    public static class KexInfo {

        public int size;

        public String auth;

        public int authSize;

        public String authName;
    }

    public static KexInfo inspectDH(TlsDHKeyExchange ex, TLSCipherInfo cipherInfo) {
        KexInfo ki = new KexInfo();
        DHParameters params = ex.dhAgreeClientPrivateKey.getParameters();
        if (ex instanceof TlsDHEKeyExchange) {
            AsymmetricKeyParameter ephermal = ((TlsDHEKeyExchange) ex).serverPublicKey;
            analyzeEphermal(ephermal, ki);
        }
        int len = params.getP().bitLength();
        ki.size = len;
        String name = KnownDHGroup.lookup(new KnownDHGroup(params.getP(), params.getG()));
        ki.authName = name;
        return ki;
    }

    public static KexInfo inspectECDH(TlsECDHKeyExchange ex) {
        KexInfo ki = new KexInfo();
        if (ex instanceof TlsECDHEKeyExchange) {
            AsymmetricKeyParameter ephermal = ((TlsECDHEKeyExchange) ex).serverPublicKey;
            analyzeEphermal(ephermal, ki);
        }
        ki.size = ecLength(ex.ecAgreePrivateKey);
        return ki;
    }

    private static void analyzeEphermal(AsymmetricKeyParameter ephermal, KexInfo ki) {
        if (ephermal == null) {
            return;
        }

        // Certificate c = ephermal.getCertificate();
        if (ephermal instanceof RSAKeyParameters) {
            ki.auth = "RSA";
            ki.authSize = rsaLength((RSAKeyParameters) ephermal);
        } else if (ephermal instanceof ECKeyParameters) {
            ki.auth = "ECDSA";
            ki.authSize = ecLength((ECKeyParameters) ephermal);
        } else if (ephermal instanceof DSAKeyParameters) {
            ki.auth = "DSA";
            ki.authSize = ((DSAKeyParameters) ephermal).getParameters().getP().bitLength();
        }
    }

    private static int ecLength(ECKeyParameters params) {
        return params.getParameters().getN().bitLength();
    }

    public static int inspectRSA(TlsRSAKeyExchange ex) {
        RSAKeyParameters params = ex.rsaServerPublicKey;
        return rsaLength(params);
    }

    private static int rsaLength(RSAKeyParameters params) {
        return params.getModulus().bitLength();
    }

    public static String inspectRSAPublicExp(TlsRSAKeyExchange ex) {
        RSAKeyParameters params = ex.rsaServerPublicKey;
        return inspectRSAPubPriv(params);
    }

    private static String inspectRSAPubPriv(RSAKeyParameters params) {
        return rsaLength(params) + " (" + params.getExponent() + ")";
    }

}
