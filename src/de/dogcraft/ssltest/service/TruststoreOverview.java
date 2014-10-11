package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import sun.security.x509.AVA;
import sun.security.x509.X500Name;
import de.dogcraft.ssltest.utils.Truststore;
import de.dogcraft.ssltest.utils.TruststoreUtil;

public class TruststoreOverview extends HttpServlet {

    class CertificateIdentifier implements Comparable<CertificateIdentifier> {

        String hash;

        String o;

        String ou;

        String cn;

        String other;

        int count;

        String pubkey;

        String country;

        public CertificateIdentifier(X509Certificate c, int count) {
            this.count = count;
            try {
                pubkey = TruststoreUtil.outputFingerprint(c.getPublicKey().getEncoded(), MessageDigest.getInstance("SHA-1"));
                pubkey = pubkey.substring(pubkey.length() - 8);
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
            pw.print("<th style='text-align: left' title='" + print + "'>");
            output(pw, cn);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, other);
            pw.print("</th>");
            pw.print("<th>");
            pw.print(hash);
            pw.print("</th>");
            pw.print("<th>");
            pw.print(pubkey);
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
        PrintWriter pw = resp.getWriter();
        pw.println("<table border='1'>");
        TreeMap<String, Truststore> store = new TreeMap<>();
        pw.print("<tr><th>C</th><th>O</th><th>OU</th><th>CN</th><th>other dn</th><th>signature</th><th>pubkey ID</th><th>#</th><th>from</th><th>to</th><th><span title='selfsigned'>S</span>");
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
                pw.print("<td>");
                outputDate(pw, cert.getNotBefore());
                pw.print("</td><td>");
                outputDate(pw, cert.getNotAfter());
                pw.print("</td><td>");
                try {
                    cert.verify(cert.getPublicKey());
                    pw.print("S");
                } catch (SignatureException ex) {

                }
                pw.print("</td>");
                for (Entry<String, Truststore> truststore : store.entrySet()) {
                    pw.print("<td>");
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
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    private void outputDate(PrintWriter pw, Date notBefore) {
        Calendar gc = Calendar.getInstance();
        gc.setTime(notBefore);
        pw.print("<span title='" + notBefore + "'>" + gc.get(Calendar.YEAR) + "</span>");
    }
}
