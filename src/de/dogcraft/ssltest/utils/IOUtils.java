package de.dogcraft.ssltest.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

public class IOUtils {

    public static byte[] get(URL u) throws IOException {
        return get(u, 0);
    }

    private static byte[] get(URL u, int depth) throws IOException {
        if (depth > 4)
            return null;
        URLConnection c = u.openConnection();
        if (u.getProtocol().equals("http") || u.getProtocol().equals("https")) {
            // TODO do we want to remove https and simply fetch the http
            // version?
            HttpURLConnection huc = (HttpURLConnection) c;
            if (huc.getResponseCode() == 301) {
                return get(new URL(huc.getHeaderField("Location")), depth + 1);
            }
            if (huc.getResponseCode() == 304)
                return null;
            if (huc.getResponseCode() == 404)
                return null;
        }
        InputStream data = c.getInputStream();
        return get(data);
    }

    public static byte[] get(InputStream data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int pos = 0;
        byte[] buf = new byte[2048];
        int len;
        int last = 0;
        while ((len = data.read(buf)) > 0) {
            pos += len;
            baos.write(buf, 0, len);
            if (pos / 10000 != last) {
                last = pos / 10000;
            }
        }
        return baos.toByteArray();
    }
}
