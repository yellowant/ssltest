package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.crypto.interfaces.DHPublicKey;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import sun.security.x509.AVA;
import sun.security.x509.X500Name;
import de.dogcraft.ssltest.utils.Truststore;
import de.dogcraft.ssltest.utils.TruststoreUtil;

public class TruststoreOverview extends HttpServlet {

    private static final long serialVersionUID = 1L;

    class CertificateIdentifier implements Comparable<CertificateIdentifier> {

        String hash;

        String o;

        String ou;

        String cn;

        String other;

        int count;

        String pubkey;

        String country;

        private X509Certificate c;

        public CertificateIdentifier(X509Certificate c, int count) {
            this.count = count;
            this.c = c;
            try {
                pubkey = TruststoreUtil.outputFingerprint(c.getPublicKey().getEncoded(), MessageDigest.getInstance("SHA-512"));
                hash = c.getSigAlgName();
                X500Name n = new X500Name(c.getSubjectX500Principal().getEncoded());
                o = n.getOrganization();
                ou = n.getOrganizationalUnit();
                cn = n.getCommonName();
                country = n.getCountry();
                other = "";
                for (AVA i : n.allAvas()) {
                    if (i.getObjectIdentifier() == X500Name.commonName_oid)
                        continue;
                    if (i.getObjectIdentifier() == X500Name.orgName_oid)
                        continue;
                    if (i.getObjectIdentifier() == X500Name.orgUnitName_oid)
                        continue;
                    if (i.getObjectIdentifier() == X500Name.countryName_oid)
                        continue;
                    if (other.length() != 0) {
                        other += ", ";
                    }
                    other += i.toRFC1779String();
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }

        public void print(PrintWriter pw, String print) {
            pw.print("<th>");
            output(pw, country);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, o);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, ou);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, cn);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, other);
            pw.print("</th>");
            pw.print("<th class=\"" + hash + "\">");
            pw.print(hash);
            pw.print("</th>");
            PublicKey pk = c.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                pw.print("<th style=\"background-color:#CCFFCC;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                int bitLength = ((RSAPublicKey) pk).getModulus().bitLength();
                String bitsec;
                if (bitLength <= 512) {
                    bitsec = "background-color: #FF4444;";
                } else if (bitLength < 1024) {
                    bitsec = "background-color: #FF8888;";
                } else if (bitLength < 2048) {
                    bitsec = "background-color: #FFCCCC;";
                } else if (bitLength < 3072) {
                    bitsec = "background-color: #FFDDCC;";
                } else if (bitLength < 4096) {
                    bitsec = "background-color: #FFEECC;";
                } else if (bitLength < 6144) {
                    bitsec = "background-color: #FFFFCC;";
                } else if (bitLength < 8192) {
                    bitsec = "background-color: #EEFFCC;";
                } else if (bitLength < 12288) {
                    bitsec = "background-color: #DDFFCC;";
                } else if (bitLength < 16384) {
                    bitsec = "background-color: #CCFFCC;";
                } else if (bitLength < 32768) {
                    bitsec = "background-color: #CCFFFF;";
                } else if (bitLength < 65536) {
                    bitsec = "background-color: #CCCCFF;";
                } else {
                    bitsec = "background-color: #8888FF;";
                }
                pw.print("<th style=\"" + bitsec + "\">");
                pw.print(bitLength);
                pw.print("</th>");
                pw.print("<th>");
                BigInteger publicExponent = ((RSAPublicKey) pk).getPublicExponent();
                if (publicExponent.bitLength() > 50) {
                    pw.print("e = [" + publicExponent.bitLength() + "bit]");
                } else {
                    pw.print("e = " + publicExponent);
                }
                pw.print("</th>");
            } else if (pk instanceof ECPublicKey) {
                pw.print("<th style=\"background-color:#CCCCFF;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                EllipticCurve ec = ((ECPublicKey) pk).getParams().getCurve();
                int bitLength = ec.getField().getFieldSize();
                String bitsec;
                if (bitLength <= 192) {
                    bitsec = "background-color: #FF4444;";
                } else if (bitLength < 224) {
                    bitsec = "background-color: #FF8888;";
                } else if (bitLength < 256) {
                    bitsec = "background-color: #FFCCCC;";
                } else if (bitLength < 320) {
                    bitsec = "background-color: #FFDDCC;";
                } else if (bitLength < 384) {
                    bitsec = "background-color: #FFEECC;";
                } else if (bitLength < 416) {
                    bitsec = "background-color: #FFFFCC;";
                } else if (bitLength < 448) {
                    bitsec = "background-color: #EEFFCC;";
                } else if (bitLength < 480) {
                    bitsec = "background-color: #DDFFCC;";
                } else if (bitLength < 512) {
                    bitsec = "background-color: #CCFFCC;";
                } else if (bitLength < 640) {
                    bitsec = "background-color: #CCFFFF;";
                } else if (bitLength < 768) {
                    bitsec = "background-color: #CCCCFF;";
                } else {
                    bitsec = "background-color: #8888FF;";
                }
                pw.print("<th style=\"" + bitsec + "\">");
                pw.print(bitLength);
                pw.print("</th>");
                pw.print("<th>");
                pw.print("Char = ?, Curve = ?");
                pw.print("</th>");
            } else if (pk instanceof DSAPublicKey) {
                pw.print("<th style=\"background-color:#FFCCCC;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                int bitLength = ((DSAPublicKey) pk).getY().bitLength();
                String bitsec;
                if (bitLength <= 512) {
                    bitsec = "background-color: #FF4444;";
                } else if (bitLength < 1024) {
                    bitsec = "background-color: #FF8888;";
                } else if (bitLength < 2048) {
                    bitsec = "background-color: #FFCCCC;";
                } else if (bitLength < 3072) {
                    bitsec = "background-color: #FFDDCC;";
                } else if (bitLength < 4096) {
                    bitsec = "background-color: #FFEECC;";
                } else if (bitLength < 6144) {
                    bitsec = "background-color: #FFFFCC;";
                } else if (bitLength < 8192) {
                    bitsec = "background-color: #EEFFCC;";
                } else if (bitLength < 12288) {
                    bitsec = "background-color: #DDFFCC;";
                } else if (bitLength < 16384) {
                    bitsec = "background-color: #CCFFCC;";
                } else if (bitLength < 32768) {
                    bitsec = "background-color: #CCFFFF;";
                } else if (bitLength < 65536) {
                    bitsec = "background-color: #CCCCFF;";
                } else {
                    bitsec = "background-color: #8888FF;";
                }
                pw.print("<th style=\"" + bitsec + "\">");
                pw.print(bitLength);
                pw.print("</th>");
                pw.print("<th>");
                pw.print("g = ?, y = ?");
                pw.print("</th>");
            } else if (pk instanceof DHPublicKey) {
                pw.print("<th style=\"background-color:#FFFFCC;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                pw.print("<th>");
                pw.print(((DHPublicKey) pk).getY().bitLength());
                pw.print("</th>");
                pw.print("<th>");
                pw.print("g = ?");
                pw.print("</th>");
            } else {
                pw.print("<th>");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                pw.print("<th>");
                pw.print("-");
                pw.print("</th>");
                pw.print("<th>");
                pw.print("-");
                pw.print("</th>");
            }
            pw.print("<th style='text-align: left' title='" + print + "'>");
            pw.print(pubkey.substring(pubkey.length() - 8));
            pw.print("</th>");
            pw.print("<th>");
            if (count != 1) {
                pw.print(count);
            } else {
                pw.print("&nbsp;");
            }
            pw.print("</th>");

        }

        private void output(PrintWriter pw, String data) {
            if (data != null)
                pw.print(data);
        }

        @Override
        public int compareTo(CertificateIdentifier target) {
            if (target == null)
                return -1;
            int i = compare(o, target.o);
            if (i != 0)
                return i;
            i = compare(ou, target.ou);
            if (i != 0)
                return i;
            i = compare(cn, target.cn);
            if (i != 0)
                return i;
            i = compare(other, target.other);
            if (i != 0)
                return i;
            return Integer.compare(count, target.count);
        }

        private int compare(String a, String b) {
            if (a == null && b == null)
                return 0;
            if (a == null)
                return -1;
            if (b == null) {
                return 1;

            }
            return a.compareTo(b);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");

        PrintWriter pw = resp.getWriter();
        pw.println("<!DOCTYPE html>");
        pw.println("<html>");
        pw.println("<head>");
        pw.println("<style type='text/css'>");
        pw.println("/* Signature Algorithm coloring */");
        pw.println(".MD2withRSA { background-color: #FFCCCC;}");
        pw.println(".MD4withRSA { background-color: #FFDDCC;}");
        pw.println(".MD5withRSA { background-color: #FFEECC;}");
        pw.println(".SHA1withRSA { background-color: #FFFFCC;}");
        pw.println(".SHA256withRSA { background-color: #EEFFCC;}");
        pw.println(".SHA384withRSA { background-color: #DDFFCC;}");
        pw.println(".SHA512withRSA { background-color: #CCFFCC;}");

        pw.println(".MD2withDSA { background-color: #FFCCCC;}");
        pw.println(".MD4withDSA { background-color: #FFDDCC;}");
        pw.println(".MD5withDSA { background-color: #FFEECC;}");
        pw.println(".SHA1withDSA { background-color: #FFFFCC;}");
        pw.println(".SHA256withDSA { background-color: #EEFFCC;}");
        pw.println(".SHA384withDSA { background-color: #DDFFCC;}");
        pw.println(".SHA512withDSA { background-color: #CCFFCC;}");

        pw.println(".SHA1withECDSA { background-color: #FFFFCC;}");
        pw.println(".SHA256withECDSA { background-color: #CCEEFF;}");
        pw.println(".SHA384withECDSA { background-color: #CCDDFF;}");
        pw.println(".SHA384withECDSA { background-color: #CCCCFF;}");

        pw.println("/* System Store coloring */");
        pw.println(".firefox{ background-color: #FFAA33;}");
        pw.println(".debian{ background-color: #BB8888;}");
        pw.println(".openbsd{ background-color: #f2eb5d;}");
        pw.println(".osx{ background-color: #DDDDFF;}");
        pw.println(".android{ background-color: #adf260;}");
        pw.println(".win{ background-color: #22affe;}");
        pw.println("</style>");
        pw.println("</head>");
        pw.println("<body>");
        pw.println("<table border='1'>");
        TreeMap<String, Truststore> store = new TreeMap<>();
        pw.print("<tr><th>C</th><th>O</th><th>OU</th><th>CN</th><th>other dn</th><th>signature</th><th>keyType</th><th>keySize</th><th>keyDetail</th><th>pubkey ID</th><th>#</th><th>from</th><th>to</th><th><span title='selfsigned'>S</span>");
        for (Entry<String, Truststore> truststore : Truststore.getStores().entrySet()) {
            if (truststore.getKey().equals("any"))
                continue;
            store.put(truststore.getKey(), truststore.getValue());
        }
        for (Entry<String, Truststore> truststore : store.entrySet()) {
            pw.print("<th><span title='");
            pw.print(truststore.getKey());
            pw.print("'>?</span></th>");
        }
        pw.println("</tr>");
        try {
            Truststore any = Truststore.getStores().get("any");
            KeyStore ks = any.getKeyStore();
            Enumeration<String> al = ks.aliases();
            TreeMap<CertificateIdentifier, Certificate> certs = new TreeMap<>();
            while (al.hasMoreElements()) {
                String alias = al.nextElement();
                X509Certificate c = (X509Certificate) ks.getCertificate(alias);
                CertificateIdentifier gname = new CertificateIdentifier(c, 1);
                int i = 2;
                while (certs.containsKey(gname)) {
                    gname.count = i++;
                }
                certs.put(gname, c);
            }
            for (Entry<CertificateIdentifier, Certificate> e : certs.entrySet()) {
                X509Certificate cert = (X509Certificate) e.getValue();
                pw.print("<tr>");
                e.getKey().print(pw, TruststoreUtil.outputFingerprint(e.getValue(), MessageDigest.getInstance("SHA-512")));
                outputDate(pw, cert.getNotBefore(), false);
                outputDate(pw, cert.getNotAfter(), true);
                pw.print("<td>");
                try {
                    cert.verify(cert.getPublicKey());
                    pw.print("S");
                } catch (SignatureException ex) {

                }
                pw.print("</td>");
                for (Entry<String, Truststore> truststore : store.entrySet()) {
                    pw.print("<td class='" + truststore.getKey().split("_")[0] + "'>");
                    pw.print("<span title='" + truststore.getKey() + "' style='color: ");
                    if (truststore.getValue().contains(e.getValue())) {
                        pw.print("green'>&#x2714;</span>");
                    } else {
                        pw.print("red'>&#x2718;</span>");
                    }
                    pw.print("</td>");
                }
                pw.println("</tr>");
            }
            pw.println("</table>");
            pw.println("</body>");
            pw.println("</html>");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    private void outputDate(PrintWriter pw, Date notBefore, boolean endOfLife) {
        String attrib = " style=\"";

        Date now = new Date();
        Long diff = notBefore.getTime() - now.getTime();

        if ( !endOfLife) {
            diff = -diff;
        }

        if (diff < 0) {
            attrib += "background-color: #FF8888;";
        } else {
            diff /= 1000;
            diff /= 86400;
            diff /= 30;

            if (diff < 3) {
                attrib += "background-color: #FFCCCC;";
            } else if (diff < 6) {
                attrib += "background-color: #FFDDCC;";
            } else if (diff < 12) {
                attrib += "background-color: #FFEECC;";
            } else if (diff < 24) {
                attrib += "background-color: #FFFFCC;";
            } else if (diff < 36) {
                attrib += "background-color: #EEFFCC;";
            } else if (diff < 60) {
                attrib += "background-color: #DDFFCC;";
            } else if (diff < 120) {
                attrib += "background-color: #CCFFCC;";
            } else if (diff < 140) {
                attrib += "background-color: #CCFFDD;";
            } else if (diff < 160) {
                attrib += "background-color: #CCFFEE;";
            } else if (diff < 180) {
                attrib += "background-color: #CCFFFF;";
            } else if (diff < 200) {
                attrib += "background-color: #CCEEFF;";
            } else if (diff < 220) {
                attrib += "background-color: #CCDDFF;";
            } else if (diff < 240) {
                attrib += "background-color: #CCCCFF;";
            } else if (diff < 260) {
                attrib += "background-color: #B0CCFF;";
            } else if (diff < 280) {
                attrib += "background-color: #9CCCFF;";
            } else if (diff < 300) {
                attrib += "background-color: #8888FF;";
            } else {
                attrib += "background-color: #FF88FF;";
            }
        }

        attrib += "\"";
        outputDate(pw, notBefore, attrib);
    }

    private void outputDate(PrintWriter pw, Date notBefore, String attrib) {
        Calendar gc = Calendar.getInstance();
        gc.setTime(notBefore);
        pw.print("<td title=\"" + notBefore + "\"" + attrib + ">" + gc.get(Calendar.YEAR) + "</td>");
    }
}
