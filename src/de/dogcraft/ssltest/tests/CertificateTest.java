package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERT61UTF8String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.JSONUtils;

public class CertificateTest {

    private static HashMap<String, Integer> kusMap = new HashMap<>();

    private static HashMap<String, String> ekusMap = new HashMap<>();

    static {
        Field[] f = KeyUsage.class.getFields();

        for (Field field : f) {
            try {
                kusMap.put(field.getName(), field.getInt(null));
            } catch (ReflectiveOperationException e) {
                e.printStackTrace();
            }
        }

        f = KeyPurposeId.class.getFields();

        for (Field field : f) {
            try {
                ekusMap.put(((KeyPurposeId) field.get(null)).getId(), field.getName());
            } catch (ReflectiveOperationException e) {
                e.printStackTrace();
            }
        }
    }

    protected static String convertToPEM(Certificate cert) throws IOException {
        final String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        final String end_cert = "\n-----END CERTIFICATE-----\n";

        return cert_begin + pemPlain(cert) + end_cert;
    }

    public static String pemPlain(ASN1Object cert) throws UnsupportedEncodingException, IOException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes("UTF-8"));
        byte[] derCert = cert.getEncoded();
        String encodeToString = encoder.encodeToString(derCert);
        return encodeToString;
    }

    private static final BigInteger TWO = new BigInteger("2");

    public static void testCerts(TestOutput pw, CertificateWrapper cert) throws IOException, NoSuchAlgorithmException {
        StringBuffer certificate = new StringBuffer();
        certificate.append("{ \"type\": \"");
        certificate.append("X.509");
        certificate.append("\", \"data\": \"");
        certificate.append(JSONUtils.jsonEscape(convertToPEM(cert.getC())));
        certificate.append("\", \"subject\": ");
        appendX500Name(certificate, cert.getC().getSubject());
        certificate.append(", \"issuer\": ");
        appendX500Name(certificate, cert.getC().getIssuer());
        certificate.append("}"); //
        pw.outputEvent("certificate", certificate.toString());

        SubjectPublicKeyInfo pkInfo = cert.getC().getTBSCertificate().getSubjectPublicKeyInfo();
        AsymmetricKeyParameter pk = PublicKeyFactory.createKey(pkInfo);

        ASN1ObjectIdentifier sigalg = cert.getC().getSignatureAlgorithm().getAlgorithm();
        String sigStr = sigalg.toString();
        if (pk instanceof RSAKeyParameters) {
            pw.outputEvent("certkey", "{ \"pkhash\":\"" + cert.getPkHash() + "\", \"sig\":\"" + sigStr + "\", \"type\":\"RSA\", \"size\":" + ((RSAKeyParameters) pk).getModulus().bitLength() + "}");
        } else if (pk instanceof DSAPublicKeyParameters) {
            pw.outputEvent("certkey", "{ \"pkhash\":\"" + cert.getPkHash() + "\", \"sig\":\"" + sigStr + "\", \"type\":\"DSA\", \"size\":" + ((DSAPublicKeyParameters) pk).getParameters().getP().bitLength() + "}");
        } else if (pk instanceof ECPublicKeyParameters) {
            pw.outputEvent("certkey", "{ \"pkhash\":\"" + cert.getPkHash() + "\", \"sig\":\"" + sigStr + "\", \"type\":\"ECDSA\", \"size\":" + ((ECPublicKeyParameters) pk).getParameters().getN().bitLength() + "}");
        }
        checkCertEncoding(pw, cert.getC());
        TBSCertificate tbs = cert.getC().getTBSCertificate();
        checkValidity(pw, tbs.getStartDate().getDate(), tbs.getEndDate().getDate());
        if (tbs.getExtensions() != null) {
            testSAN(pw, tbs);
            RevocationChecks.testCRL(pw, tbs);
            testAIA(pw, tbs, cert);
        }
        // TODO re-implement and display
        // testBasicConstraints(pw, tbs);
        // testKeyUsage(pw, tbs);
        // testExtendedKeyUsage(pw, tbs);

    }

    private static void appendX500Name(StringBuffer certificate, X500Name subject) {
        certificate.append("[");
        boolean first = true;
        for (RDN rdn : subject.getRDNs()) {
            if (first) {
                first = false;
            } else {
                certificate.append(", ");
            }
            certificate.append("{");
            boolean firstAVA = true;
            for (AttributeTypeAndValue ava : rdn.getTypesAndValues()) {
                if (firstAVA) {
                    firstAVA = false;
                } else {
                    certificate.append(", ");
                }
                String oid = ava.getType().toString();
                certificate.append("\"");
                certificate.append(JSONUtils.jsonEscape(oid));
                certificate.append("\":");
                ASN1Encodable val = ava.getValue();
                if (val instanceof DERPrintableString) {
                    certificate.append("\"");
                    certificate.append(((DERPrintableString) val).getString());
                    certificate.append("\"");
                } else if (val instanceof DERUTF8String) {
                    certificate.append("\"");
                    certificate.append(((DERUTF8String) val).getString());
                    certificate.append("\"");
                } else if (val instanceof DERIA5String) {
                    certificate.append("\"");
                    certificate.append(((DERIA5String) val).getString());
                    certificate.append("\"");
                } else if (val instanceof DERT61String) {
                    certificate.append("\"");
                    certificate.append(((DERT61String) val).getString());
                    certificate.append("\"");
                } else if (val instanceof DERT61UTF8String) {
                    certificate.append("\"");
                    certificate.append(((DERT61UTF8String) val).getString());
                    certificate.append("\"");
                } else if (val instanceof DERBMPString) {
                    certificate.append("\"");
                    certificate.append(((DERBMPString) val).getString());
                    certificate.append("\"");
                } else {
                    certificate.append("null");
                }
            }
            certificate.append("}");
        }
        certificate.append("]");

    }

    private static void checkCertEncoding(TestOutput pw, Certificate cert) {
        pw.enterTest("Encoding");
        BigInteger v = cert.getVersion().getValue();
        if (v.equals(BigInteger.ZERO)) {
            pw.outputEvent("certtype", String.format("{ \"type\": \"v1-Certificate\", \"points\": %d }", -3));
        } else if (v.equals(BigInteger.ONE)) {
            pw.outputEvent("certtype", String.format("{ \"type\": \"v2-Certificate\", \"points\": %d }", -1));
        } else if (v.equals(TWO)) {
            pw.outputEvent("certtype", String.format("{ \"type\": \"v3-Certificate\", \"points\": %d }", 1));
        }
        pw.exitTest("Encoding", TestResult.IGNORE);
    }

    private static final long MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

    private static void checkValidity(TestOutput pw, Date start, Date end) {
        pw.enterTest("Validity Period");
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss 'UTC'");
        pw.outputEvent("certvalidity", String.format("{ \"start\": \"%s\", \"end\": \"%s\" }", sdf.format(start), sdf.format(end)));
        Date now = new Date();
        if (start.before(now) && end.after(now)) {
            pw.output("Certificate is currently valid.");
        }
        if ( !start.before(now)) {
            pw.output("Not yet valid", -1);
        } else if ( !end.after(now)) {
            pw.output("Expired", -1);
            long expiry = now.getTime() - end.getTime();
            if (expiry > 90 * MILLISECONDS_PER_DAY) {
                pw.output("Expired for 3 months", -10);
            } else if (expiry > 30 * MILLISECONDS_PER_DAY) {
                pw.output("Expired for 1 month", -5);
            } else if (expiry > 7 * MILLISECONDS_PER_DAY) {
                pw.output("Expired for 1 week", -1);
            }
        } else {
            long validity = end.getTime() - now.getTime();
            if (validity > 90 * MILLISECONDS_PER_DAY) {
                pw.output("Still valid for more than 3 months (max)", 2);
            } else if (validity > 30 * MILLISECONDS_PER_DAY) {
                pw.output("Still valid for more than 1 month", 1);
            } else {
                pw.output("Still valid for more less than 1 month", 0);
            }

            long validFor = now.getTime() - start.getTime();
            if (validFor > 3 * 30 * MILLISECONDS_PER_DAY) {
                pw.output("Certificate has been valid for at least 3 months (max)", 2);
            } else if (validFor > 30 * MILLISECONDS_PER_DAY) {
                pw.output("Certificate has been valid for at least 1 month", 1);
            } else {
                pw.output("Certificate has been valid for less than 1 month", 0);
            }

            long period = end.getTime() - start.getTime();
            if (period > 37 * 30 * MILLISECONDS_PER_DAY) {
                pw.output("Total validity for more than 3 years", -2);
            } else if (period > 24 * 30 * MILLISECONDS_PER_DAY) {
                pw.output("Total validity for more than 2 years (max)", 3);
            } else if (period > 12 * 30 * MILLISECONDS_PER_DAY) {
                pw.output("Total validity for more than 1 years", 2);
            } else if (period > 6 * 30 * MILLISECONDS_PER_DAY) {
                pw.output("Total validity for more than 6 months ", 1);
            } else {
                pw.output("Total validity for less 6 months", 0);
            }
        }

        pw.exitTest("Validity Period", TestResult.IGNORE);
    }

    private static void testAIA(TestOutput pw, TBSCertificate tbs, CertificateWrapper c) {
        Extension ext = extractCertExtension(tbs, Extension.authorityInfoAccess);

        if (ext != null) {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            AccessDescription[] data = aia.getAccessDescriptions();
            for (AccessDescription accessDescription : data) {
                GeneralName location = accessDescription.getAccessLocation();
                String value = parseGeneralName(location);
                pw.outputEvent("authorityInfoAccess", String.format("{ \"type\": \"%s\", \"loc\": \"%s\" }", accessDescription.getAccessMethod(), value));
                if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    RevocationChecks.testOCSP(pw, tbs, c, value);
                }
            }
        }
    }

    private static String parseGeneralName(GeneralName val) {
        String value;
        switch (val.getTagNo()) {
        case GeneralName.rfc822Name:
        case GeneralName.dNSName:
        case GeneralName.uniformResourceIdentifier:
            value = DERIA5String.getInstance(val.getName()).getString();
            break;
        case GeneralName.directoryName:
            value = X500Name.getInstance(val.getName()).toString();
            break;
        default:
            value = "unknown";
        }
        return value;
    }

    private static void outputCritical(TestOutput pw, Extension ext) {
        if (ext.isCritical()) {
            pw.output("is critical");
        } else {
            pw.output("is not critical");
        }
    }

    private static void testSAN(TestOutput pw, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.subjectAlternativeName);

        pw.enterTest("SubjectAltNames");
        StringBuffer text = new StringBuffer("{ \"value\":");
        if (ext != null) {
            text.append("[");
            float mult = testCrit(false, pw, "subjectAlternativeNames", ext);
            ASN1Sequence ds = ASN1Sequence.getInstance(ext.getParsedValue());

            @SuppressWarnings("unchecked")
            Enumeration<ASN1Encodable> obj = ds.getObjects();
            while (obj.hasMoreElements()) {
                GeneralName genName = GeneralName.getInstance(obj.nextElement());
                text.append("{ \"type\": \"" + genName.getTagNo() + "\"");
                if (genName.getTagNo() == GeneralName.dNSName) {
                    text.append(", \"value\": \"" + ((ASN1String) genName.getName()).getString() + "\"");
                } else if (genName.getTagNo() == GeneralName.directoryName) {
                    text.append(", \"value\": ");
                    appendX500Name(text, (X500Name) genName.getName());
                } else if (genName.getTagNo() == GeneralName.otherName) {
                    ASN1Sequence seq = (ASN1Sequence) genName.getName();
                    System.out.println("OtherName");
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq.getObjectAt(0);
                    text.append(", \"typeOID\": \"" + oid.toString() + "\"");
                    String name = ((ASN1String) ((ASN1TaggedObject) seq.getObjectAt(1)).getObject()).getString();
                    text.append(", \"value\": \"" + name + "\"");
                }
                text.append("}");
                if (obj.hasMoreElements()) {
                    text.append(", ");
                }
            }
            text.append("]}");
        } else {
            text.append("\"undefined\"}");
        }
        pw.outputEvent("certSANs", text.toString());
    }

    private static void testExtendedKeyUsage(TestOutput pw, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.extendedKeyUsage);

        if (ext != null) {
            pw.enterTest("ExtendedKeyUsage");
            outputCritical(pw, ext);
            float mult = testCrit(false, pw, "extendedKeyUsage", ext);
            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());

            KeyPurposeId[] kpi = eku.getUsages();
            StringBuffer ekus = new StringBuffer();
            boolean sslserv = false;
            for (KeyPurposeId keyPurposeId : kpi) {
                if (keyPurposeId.equals(KeyPurposeId.id_kp_serverAuth)) {
                    sslserv = true;
                }
                String s = ekusMap.get(keyPurposeId.getId());
                if (s != null) {
                    ekus.append(s);
                } else {
                    ekus.append("Unknown (" + keyPurposeId.getId() + ")");
                }
                ekus.append(", ");
            }
            TestResult res = new TestResult(mult);
            if ( !sslserv) {
                pw.output("Strange Extended Key usage (serverAuth missing)");
                res = TestResult.FAILED;
            }
            pw.output("ExtendedKeyUsage: " + ekus.toString());
            pw.exitTest("ExtendedKeyUsage", res);

        }
    }

    private static void testKeyUsage(TestOutput pw, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.keyUsage);
        pw.enterTest("KeyUsage");
        if (ext != null) {
            outputCritical(pw, ext);

            KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());
            StringBuffer kus = new StringBuffer();
            for (Entry<String, Integer> ent : kusMap.entrySet()) {
                if (ku.hasUsages(ent.getValue())) {
                    kus.append(ent.getKey());
                    kus.append(" ");
                }
            }
            pw.output("Key usages: " + kus.toString());
            TestResult passage = new TestResult(1);
            if ( !ku.hasUsages(KeyUsage.keyAgreement | KeyUsage.keyEncipherment)) {
                pw.output("Strange key usage flags for an ssl server certificate.");
                passage = TestResult.FAILED;
            }
            pw.exitTest("KeyUsage", passage);
        } else {
            pw.output("Keyusage extension not present.");
            pw.exitTest("KeyUsage", TestResult.FAILED);
        }
    }

    private static void testBasicConstraints(TestOutput pw, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.basicConstraints);

        pw.enterTest("BasicConstraints");
        if (ext == null) {
            pw.output("Basic constraints missing.", 0);
            pw.exitTest("BasicConstraints", TestResult.IGNORE);
            return;
        }

        BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
        if (bc.isCA()) {
            pw.output("Your server certificate is a CA!!!", -15);
            pw.exitTest("BasicConstraints", TestResult.FAILED);
        } else if (ext.isCritical()) {
            pw.output("Your server certificate not a CA.", 15);
            pw.exitTest("BasicConstraints", TestResult.IGNORE);
        } else {
            pw.output("Your server certificate not a CA, but it's not critical?", -5);
            pw.exitTest("BasicConstraints", TestResult.FAILED);
        }
    }

    private static Extension extractCertExtension(TBSCertificate tbs, ASN1ObjectIdentifier oid) {
        Extension ext = tbs.getExtensions().getExtension(oid);
        return ext;
    }

    private static float testCrit(boolean crit, TestOutput pw, String type, Extension ext) {
        if ( !ext.isCritical() && crit) {
            pw.output("extension " + type + " is marked non-critical, when it should be");
            return 0.5f;
        }
        return 1f;
    }

}
