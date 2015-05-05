package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.Hashtable;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.DSA;
import org.bouncycastle.jcajce.provider.asymmetric.EC;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

import de.dogcraft.ssltest.utils.JSONUtils;

public class OIDs {

    public static void outputOids(HttpServletResponse resp) throws IOException {
        resp.setContentType("text/javascript");
        PrintWriter out = resp.getWriter();
        out.print("var dnOIDs = ");
        out.print(OIDs.generateDNOids());
        out.println(";");
        out.print("var sigOIDs = ");
        generateSigOIDs(out);
        out.println(";");

    }

    private static void generateSigOIDs(final PrintWriter out) {
        ConfigurableProvider provider = new ConfigurableProvider() {

            @Override
            public void setParameter(String parameterName, Object parameter) {

            }

            @Override
            public boolean hasAlgorithm(String type, String name) {
                return true;
            }

            @Override
            public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter) {

            }

            @Override
            public void addAlgorithm(String key, String value) {
                String pfx = "Alg.Alias.Signature.OID.";
                if (key.startsWith(pfx)) {
                    String oid = key.substring(pfx.length());
                    out.print("\"");
                    out.print(oid);
                    out.print("\":\"");
                    out.print(JSONUtils.jsonEscape(value));
                    out.print("\"");
                    out.print(", ");
                }
            }
        };
        out.print("{");
        new RSA.Mappings().configure(provider);
        new EC.Mappings().configure(provider);
        new DSA.Mappings().configure(provider);
        out.print("}");
    }

    public static String generateDNOids() {
        try {
            Field f = org.bouncycastle.asn1.x500.style.BCStyle.class.getDeclaredField("DefaultSymbols");
            f.setAccessible(true);
            Hashtable<ASN1ObjectIdentifier, String> symbols = (Hashtable<ASN1ObjectIdentifier, String>) f.get(null); // ASN1ObjectIdentifier -> String
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

}
