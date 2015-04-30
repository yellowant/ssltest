package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERT61UTF8String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;

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

    public static String generateDNOids() {
        try {
            Field f = org.bouncycastle.asn1.x500.style.BCStyle.class.getDeclaredField("DefaultSymbols");
            f.setAccessible(true);
            Hashtable symbols = (Hashtable) f.get(null); // ASN1ObjectIdentifier
                                                         // -> String
            Set<Map.Entry<ASN1ObjectIdentifier, String>> set = symbols.entrySet();
            StringBuffer buf = new StringBuffer();
            buf.append("{");
            boolean fst = true;
            for (Entry<ASN1ObjectIdentifier, String> entry : set) {
                if (fst) {
                    fst = false;
                } else {
                    buf.append(", ");
                }
                String oid = entry.getKey().toString();
                String text = entry.getValue();
                buf.append("\"");
                buf.append(JSONUtils.jsonEscape(oid));
                buf.append("\":\"");
                buf.append(JSONUtils.jsonEscape(text));
                buf.append("\"");

            }
            buf.append("}");
            return buf.toString();

        } catch (ReflectiveOperationException e) {
            e.printStackTrace();
        }
        return null;
    }

    protected static String convertToPEM(Certificate cert) throws IOException {
        final String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        final String end_cert = "\n-----END CERTIFICATE-----\n";

        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes("UTF-8"));

        byte[] derCert = cert.getEncoded();
        return cert_begin + encoder.encodeToString(derCert) + end_cert;
    }

    private static final BigInteger TWO = new BigInteger("2");

    public static void testCerts(TestOutput pw, Certificate[] c) throws IOException {

        int certindex = 0;
        for (Certificate cert : c) {
            StringBuffer certificate = new StringBuffer();
            certificate.append("{ \"index\": ");
            certificate.append(Integer.toString(certindex++));
            certificate.append(", \"type\": \"");
            certificate.append("X.509");
            certificate.append("\", \"data\": \"");
            certificate.append(JSONUtils.jsonEscape(convertToPEM(cert)));
            certificate.append("\", \"subject\": ");
            appendX500Name(certificate, cert.getSubject());
            certificate.append(", \"issuer\": ");
            appendX500Name(certificate, cert.getIssuer());
            certificate.append("}"); //
            pw.outputEvent("certificate", certificate.toString());
        }

        for (int i = 0; i < c.length; i++) {
            SubjectPublicKeyInfo pk = c[i].getTBSCertificate().getSubjectPublicKeyInfo();
            if (pk.getAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)) {
                RSAPublicKey rpk = RSAPublicKey.getInstance(pk.getPublicKeyData().getBytes());
                pw.outputEvent("certkey", "{ \"index\":" + i + ", \"type\":\"RSA\", \"size\":" + rpk.getModulus().bitLength() + "}");
            }
            checkCertEncoding(pw, i, c[i]);
            TBSCertificate tbs = c[i].getTBSCertificate();
            checkValidity(pw, i, tbs.getStartDate().getDate(), tbs.getEndDate().getDate());
            checkRevocation(pw, i, tbs);

            testBasicConstraints(pw, tbs);
            testKeyUsage(pw, tbs);
            testExtendedKeyUsage(pw, tbs);
            testCRL(pw, tbs);
            testSAN(pw, tbs);
            testAIA(pw, tbs);
        }

        pw.enterTest("Verifying extensions");

        HashMap<String, TestResult> tr = pw.getSubresults();
        if (tr == null) {
            tr = new HashMap<String, TestResult>();
        }

        float val = 0;
        for (Entry<String, TestResult> e : tr.entrySet()) {
            val += e.getValue().getRes();
        }

        if (tr.size() > 0) {
            val /= tr.size();
        }

        pw.exitTest("Verifying extensions", new TestResult(val));
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

    private static void checkRevocation(TestOutput pw, int index, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.cRLDistributionPoints);
        pw.enterTest("Revocation");
        int crlCount = 0;

        if (ext != null) {
            testCrit(false, pw, "CRLDistPoints", ext);

            DistributionPoint[] points = CRLDistPoint.getInstance(ext.getParsedValue()).getDistributionPoints();
            for (DistributionPoint distributionPoint : points) {
                pw.outputEvent("certcrl", String.format("{ \"index\": %d, \"crl\": \"%s\" }", index, distributionPoint.getDistributionPoint().toString()));

                DistributionPointName point = distributionPoint.getDistributionPoint();
                if (point.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] gns = GeneralNames.getInstance(point.getName()).getNames();
                    for (GeneralName gn : gns) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = ((ASN1String) gn.getName()).getString();
                            pw.output("CRL: " + url);
                        } else {
                            pw.output("Strange CRL Name Type: " + gn.getTagNo());
                        }
                    }
                } else {
                    pw.output("Strange CRL Type: " + point.getType());
                }

                pw.output("CRL-issuer: " + distributionPoint.getCRLIssuer());
                crlCount++;
            }
        }

        if (crlCount != 0) {
            pw.output("Your certificate contains CRL info", 2);
        } else {
            pw.output("Your certificate does not contain CRL info");
        }

        pw.exitTest("Revocation", TestResult.FAILED);
    }

    private static void checkCertEncoding(TestOutput pw, int index, Certificate cert) {
        pw.enterTest("Encoding");
        BigInteger v = cert.getVersion().getValue();
        if (v.equals(BigInteger.ZERO)) {
            pw.outputEvent("certtype", String.format("{ \"index\": %d, \"type\": \"v1-Certificate\", \"points\": %d }", index, -3));
        } else if (v.equals(BigInteger.ONE)) {
            pw.outputEvent("certtype", String.format("{ \"index\": %d, \"type\": \"v2-Certificate\", \"points\": %d }", index, -1));
        } else if (v.equals(TWO)) {
            pw.outputEvent("certtype", String.format("{ \"index\": %d, \"type\": \"v3-Certificate\", \"points\": %d }", index, 1));
        }
        pw.exitTest("Encoding", TestResult.IGNORE);
    }

    private static final long MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

    private static void checkValidity(TestOutput pw, int index, Date start, Date end) {
        pw.enterTest("Validity Period");
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss 'UTC'");
        pw.outputEvent("certvalidity", String.format("{ \"index\": %d, \"start\": \"%s\", \"end\": \"%s\" }", index, sdf.format(start), sdf.format(end)));
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

    private static void testAIA(TestOutput pw, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.authorityInfoAccess);

        if (ext != null) {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            pw.enterTest("authorityInfoAccess");
            outputCritical(pw, ext);
            AccessDescription[] data = aia.getAccessDescriptions();
            for (AccessDescription accessDescription : data) {
                if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    pw.output("type: OCSP");
                } else {
                    pw.output("type: " + accessDescription.getAccessMethod());
                }
                pw.output("loc: " + accessDescription.getAccessLocation());
            }
            pw.exitTest("authorityInfoAccess", TestResult.IGNORE);
        }
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
        if (ext != null) {
            float mult = testCrit(false, pw, "subjectAlternativeNames", ext);
            outputCritical(pw, ext);

            ASN1Sequence ds = ASN1Sequence.getInstance(ext.getParsedValue());

            @SuppressWarnings("unchecked")
            Enumeration<ASN1Encodable> obj = ds.getObjects();

            while (obj.hasMoreElements()) {
                GeneralName genName = GeneralName.getInstance(obj.nextElement());
                if (genName.getTagNo() == GeneralName.dNSName) {
                    pw.output("DNS: " + ((ASN1String) genName.getName()).getString());
                } else if (genName.getTagNo() != 0) {
                    pw.output("Unknown SAN name tag" + genName.getTagNo());
                } else {
                    pw.output("Unknown SAN name " + genName.getName());
                }
            }

            pw.exitTest("SubjectAltNames", new TestResult(mult));
        } else {
            pw.exitTest("SubjectAltNames", TestResult.FAILED);
        }
    }

    private static void testCRL(TestOutput pw, TBSCertificate tbs) {
        Extension ext = extractCertExtension(tbs, Extension.cRLDistributionPoints);
        pw.enterTest("CRLDistrib");
        if (ext != null) {
            float mult = testCrit(false, pw, "CRLDistPoints", ext);
            outputCritical(pw, ext);

            DistributionPoint[] points = CRLDistPoint.getInstance(ext.getParsedValue()).getDistributionPoints();
            for (DistributionPoint distributionPoint : points) {
                pw.output("CRL-name: " + distributionPoint.getDistributionPoint().toString().replace("\n", "\ndata: "));
                pw.output("CRL-issuer: " + distributionPoint.getCRLIssuer());
            }
            pw.exitTest("CRLDistrib", new TestResult(mult));
        } else {
            pw.output("Missing CRLs");
            pw.exitTest("CRLDistrib", TestResult.FAILED);
        }
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
