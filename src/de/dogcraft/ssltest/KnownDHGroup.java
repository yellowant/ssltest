package de.dogcraft.ssltest;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;

public class KnownDHGroup {

    String name;

    BigInteger p;

    BigInteger g;

    public KnownDHGroup(File f) throws IOException {
        name = f.getName().split(".txt")[0];
        BufferedReader br = new BufferedReader(new FileReader(f));
        readHeader(br);
        br.close();
    }

    public KnownDHGroup(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
    }

    private void readHeader(BufferedReader br) throws IOException {
        StringBuffer res = new StringBuffer();
        String line = br.readLine();
        if (line == null) {
            return;
        }
        res.append(line);
        while ((line = br.readLine()) != null) {
            if (line.startsWith(" ")) {
                res.append(line);
            } else {
                handleHeader(res);
                res = res.delete(0, res.length());
                res.append(line);
            }
        }
        handleHeader(res);
    }

    private void handleHeader(StringBuffer res) {
        String[] header = res.toString().split(":", 2);
        String key = header[0];
        if (key.equals("P")) {
            p = new BigInteger(header[1].replace(" ", ""), 16);
        } else if (key.equals("G")) {
            g = new BigInteger(header[1].replace(" ", ""), 16);
        } else if (key.equals("Type")) {
            if ( !header[1].trim().equals("modp")) {
                throw new Error(header[1]);
            }
        } else if (key.equals("Name")) {
        } else {
            throw new Error(header[1]);
        }
    }

    public String getName() {
        return name;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((p == null) ? 0 : p.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KnownDHGroup other = (KnownDHGroup) obj;
        if (g == null) {
            if (other.g != null)
                return false;
        } else if ( !g.equals(other.g))
            return false;
        if (p == null) {
            if (other.p != null)
                return false;
        } else if ( !p.equals(other.p))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return name + ": P=" + p + ", G=" + g;
    }

    private static HashMap<KnownDHGroup, KnownDHGroup> set = new HashMap<KnownDHGroup, KnownDHGroup>();

    static {
        File f = new File("params/dh");
        for (File f1 : f.listFiles()) {
            if ( !f1.getName().contains("modp")) {
                continue;
            }
            System.out.println(f1);
            try {
                KnownDHGroup gr = new KnownDHGroup(f1);
                set.put(gr, gr);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static String lookup(KnownDHGroup gr) {
        KnownDHGroup knownDHGroup = set.get(gr);
        if (knownDHGroup == null) {
            return null;
        }
        return knownDHGroup.getName();
    }

    public static void main(String[] args) throws IOException {
        System.out.println(new KnownDHGroup(new File("dhGroups/rfc3526-1536bit.txt")));
    }
}
