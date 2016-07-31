package de.dogcraft.ssltest.utils;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class TruststoreGroup {

    TreeMap<String, Truststore> tm;

    public TruststoreGroup(String name, File[] list) throws GeneralSecurityException, IOException {
        if (name.equals("osx")) {
            tm = new TreeMap<>(new Comparator<String>() {

                @Override
                public int compare(String o1, String o2) {
                    o1 = mutate(o1);
                    o2 = mutate(o2);
                    return o1.compareTo(o2);
                }

                private String mutate(String o1) {
                    return o1.replaceFirst("^([0-9]+)_([0-9])_", "$1_0$2_")//
                    .replaceFirst("^([0-9])_([0-9]+)_", "0$1_$2_");
                }
            });
        } else if (name.equals("win")) {
            tm = new TreeMap<>(new Comparator<String>() {

                @Override
                public int compare(String o1, String o2) {
                    o1 = mutate(o1);
                    o2 = mutate(o2);
                    return o1.compareTo(o2);
                }

                private String mutate(String o1) {
                    return o1.replaceFirst("^xp", "5").replaceFirst("^vista", "6").replaceFirst("^([0-9])_", "0$1");
                }
            });
        } else {
            tm = new TreeMap<>();
        }
        for (int i = 0; i < list.length; i++) {
            if (list[i].isDirectory() && list[i].getName().startsWith(name)) {
                String[] parts = list[i].getName().split("_", 2);
                try {
                    tm.put(parts[1], new Truststore(list[i], this, list[i].getName()));
                } catch (Exception e) {
                    System.out.println("Could not load truststore: " + list[i].getName());
                    e.printStackTrace();
                }
            }
        }
        Set<String> keys = new TreeSet<>(tm.keySet());
        Truststore last = null;
        for (String key : keys) {
            if (last == null) {
                last = tm.get(key);
            } else {
                Truststore ne = tm.get(key);
                if (ne.hasSameContents(last)) {
                    tm.remove(key);
                } else {
                    last = ne;
                }

            }
        }
    }

    private static final Map<String, TruststoreGroup> stores;

    private static final Truststore anyTS;
    static {
        HashMap<String, TruststoreGroup> storesm = new HashMap<>();
        try {
            File f = new File("trusts");
            File[] files = f.listFiles();
            if (null != files) {
                for (File fs : files) {
                    if ( !fs.isDirectory() || fs.getName().startsWith("_")) {
                        continue;
                    }
                    String[] parts = fs.getName().split("_", 2);
                    TruststoreGroup tg = storesm.get(parts[0]);
                    if (tg == null) {
                        tg = new TruststoreGroup(parts[0], files);
                        storesm.put(parts[0], tg);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        Truststore any = null;
        try {
            any = new Truststore();
            any.initAny(storesm.values());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        anyTS = any;
        stores = Collections.unmodifiableMap(storesm);
    }

    public static Map<String, TruststoreGroup> getStores() {
        return stores;
    }

    public static Truststore getAnyTruststore() {
        return anyTS;
    }

    public float contains(Certificate value) {
        float trustValue = 0;
        for (Truststore i : tm.values()) {
            if (i.contains(value)) {
                trustValue += 1;
            }
            trustValue /= 2;
        }
        return trustValue;
    }

    public TreeMap<String, Truststore> getContainedTables() {
        return tm;
    }
}
