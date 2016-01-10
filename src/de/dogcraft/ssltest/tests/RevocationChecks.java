package de.dogcraft.ssltest.tests;

import static de.dogcraft.ssltest.tests.CertificateTest.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRLEntry;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.TBSCertificate;

import sun.security.x509.X509CRLImpl;
import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.FileCache;
import de.dogcraft.ssltest.utils.JSONUtils;

public class RevocationChecks {

    private static final FileCache crls = new FileCache(new File("crls"));

    public static void testCRL(TestOutput pw, TBSCertificate tbs) throws IOException {
        Extension ext = tbs.getExtensions().getExtension(Extension.cRLDistributionPoints);
        if (ext != null) {
            DistributionPoint[] points = CRLDistPoint.getInstance(ext.getParsedValue()).getDistributionPoints();
            for (DistributionPoint distributionPoint : points) {
                DistributionPointName dp = distributionPoint.getDistributionPoint();
                if (dp.getType() != DistributionPointName.FULL_NAME) {
                    pw.outputEvent("warning", "crl name malfomed");
                    continue;
                }
                GeneralNames gn = (GeneralNames) dp.getName();
                for (GeneralName n : gn.getNames()) {
                    if (n.getTagNo() != GeneralName.uniformResourceIdentifier) {
                        pw.outputEvent("warning", "crl distribution point unknown");
                        continue;
                    }

                    String url = DERIA5String.getInstance(n.getName()).getString();
                    URL u = new URL(url);
                    crls.put(url, u);
                    byte[] crl = crls.get(url);
                    String status = "not revoked";
                    try {
                        X509CRLImpl c = new X509CRLImpl(crl);
                        Set<X509CRLEntry> revokedCertificates = c.getRevokedCertificates();
                        if (revokedCertificates != null)
                            for (X509CRLEntry e : revokedCertificates) {
                                if (Arrays.equals(c.getIssuerX500Principal().getEncoded(), tbs.getIssuer().getEncoded()) && e.getSerialNumber().equals(tbs.getSerialNumber().getValue())) {
                                    // found!
                                    status = "revoked: " + e.getRevocationDate() + " because " + e.getRevocationReason();
                                }
                            }
                    } catch (CRLException e) {
                        e.printStackTrace();
                    }
                    pw.outputEvent("crl", String.format("{\"url\": \"%s\", \"issuer\": \"%s\", \"status\": \"%s\"}",//
                            JSONUtils.jsonEscape(url), JSONUtils.jsonEscape(distributionPoint.getCRLIssuer() == null ? "null" : distributionPoint.getCRLIssuer().toString()), status));
                }
            }
        }
    }

    public static void testOCSP(TestOutput pw, TBSCertificate tbs, CertificateWrapper c, String url) {

        String HASH_TYPE = "SHA-1";

        AlgorithmIdentifier HASH_OID = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        // TODO test other algorithms
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_TYPE);
            byte[] nameHash = md.digest(c.getIssuer().getSubject().getEncoded());
            md.reset();
            byte[] keyHash = md.digest(c.getIssuer().getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
            CertID ci = new CertID(HASH_OID, new DEROctetString(nameHash), new DEROctetString(keyHash), tbs.getSerialNumber());
            Request r = new Request(ci, null);
            TBSRequest tbsr = new TBSRequest(null, new DERSequence(new ASN1Encodable[] {
                r
            }), (Extensions) null);
            OCSPRequest ocr = new OCSPRequest(tbsr, null);
            URL u = new URL(url);

            if (u.getProtocol().equals("http")) {
                HttpURLConnection huc = (HttpURLConnection) u.openConnection();
                huc.setDoOutput(true);
                OutputStream o = huc.getOutputStream();
                o.write(ocr.getEncoded());
                o.flush();
                InputStream in = huc.getInputStream();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                {
                    byte[] buf = new byte[256];
                    int len = 0;
                    while ((len = in.read(buf)) > 0) {
                        baos.write(buf, 0, len);
                    }
                }
                OCSPResponse re = OCSPResponse.getInstance(baos.toByteArray());
                BigInteger res = re.getResponseStatus().getValue();
                String status = "unknown";
                if (res.intValue() == OCSPResponseStatus.SUCCESSFUL) {
                    if (re.getResponseBytes().getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                        BasicOCSPResponse bop = BasicOCSPResponse.getInstance(re.getResponseBytes().getResponse().getOctets());
                        ASN1Sequence as = bop.getTbsResponseData().getResponses();
                        ASN1Encodable[] array = as.toArray();
                        boolean found = false;
                        for (ASN1Encodable asn1Encodable : array) {
                            SingleResponse rs = SingleResponse.getInstance(asn1Encodable);
                            CertID cid = rs.getCertID();
                            AlgorithmIdentifier aid = cid.getHashAlgorithm();
                            if ( !aid.getAlgorithm().equals(HASH_OID.getAlgorithm())) {
                                pw.outputEvent("warning", "hash ocsp response does not match");
                            } else {
                                if (Arrays.equals(keyHash, cid.getIssuerKeyHash().getOctets()) //
                                        &&
                                        Arrays.equals(nameHash, cid.getIssuerNameHash().getOctets()) //
                                        && cid.getSerialNumber().equals(tbs.getSerialNumber())) {
                                    // Our response was found !! :)
                                    CertStatus cs = rs.getCertStatus();
                                    if (cs.getTagNo() == 0) {
                                        status = "good";
                                    } else if (cs.getTagNo() == 1) {
                                        RevokedInfo ri = RevokedInfo.getInstance(cs.getStatus());
                                        try {
                                            status = "revoked at " + ri.getRevocationTime().getDate() + " because " + ri.getRevocationReason().toString();
                                        } catch (ParseException e) {
                                            e.printStackTrace();
                                        }
                                    } else if (cs.getTagNo() == 2) {
                                        status = "unkown-info";
                                    } else {
                                        status = "found-unkown";
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if ( !found) {
                            status = "cert not found in OCSP response";
                        }
                    } else {
                        status = "OCSP response type not understood";
                    }
                } else if (res.intValue() == OCSPResponseStatus.MALFORMED_REQUEST) {
                    status = "malformed request";
                } else if (res.intValue() == OCSPResponseStatus.UNAUTHORIZED) {
                    status = "unauthorized";
                }
                pw.outputEvent("OCSP", String.format("{ \"url\": \"%s\", \"state\": \"%s\", \"request\":\"%s\", \"response\":\"%s\" }", //
                        url, status, JSONUtils.jsonEscape(pemPlain(ocr)), JSONUtils.jsonEscape(pemPlain(re))));

            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
