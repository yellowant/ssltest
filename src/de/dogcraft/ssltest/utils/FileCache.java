package de.dogcraft.ssltest.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Base64;

public class FileCache {

    File base;

    public FileCache(File name) {
        this.base = name;
        name.mkdirs();
    }

    public synchronized void put(String name, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(address(name))) {
            fos.write(data);
        }
    }

    private String addresser(String name) throws UnsupportedEncodingException {
        return Base64.getEncoder().encodeToString(name.getBytes("UTF-8")).replace("/", "_");
    }

    public synchronized byte[] get(String name) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (FileInputStream fis = new FileInputStream(address(name))) {
            byte[] buf = new byte[2048];
            int len;
            while ((len = fis.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }
        }
        return baos.toByteArray();
    }

    public synchronized void put(String name, InputStream data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(address(name))) {
            byte[] buf = new byte[2048];
            int len;
            while ((len = data.read(buf)) > 0) {
                fos.write(buf, 0, len);
            }
        }
    }

    private File address(String name) throws UnsupportedEncodingException {
        return new File(base, addresser(name));
    }

    public void put(String name, URL u) throws IOException {
        URLConnection c = u.openConnection();
        if (u.getProtocol().equals("http") || u.getProtocol().equals("https")) {
            // TODO do we want to remove http and simply fetch the http version?
            HttpURLConnection huc = (HttpURLConnection) c;
            huc.setIfModifiedSince(address(name).lastModified());
            if (huc.getResponseCode() == 301) {
                put(name, new URL(huc.getHeaderField("Location")));
                return;
            }
            if (huc.getResponseCode() == 304)
                return;
        }
        System.out.println("Fetching URL to cache: " + u);
        put(name, c.getInputStream());
        System.out.println("Fetched URL to cache: " + u);
    }

}
