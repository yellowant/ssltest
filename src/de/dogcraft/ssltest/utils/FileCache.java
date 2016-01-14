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

import de.dogcraft.ssltest.tests.TestOutput;

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
        File file = address(name);
        if ( !file.exists()) {
            return null;
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[2048];
            int len;
            while ((len = fis.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }
        }
        return baos.toByteArray();
    }

    public void put(String name, InputStream data, TestOutput dcn, int tlen) throws IOException {
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
                dcn.outputEvent("dwnProgress", "{\"url\":\"" + JSONUtils.jsonEscape(name) + "\", \"current\":" + 10000 * (pos / 10000) + ", \"total\":" + tlen + "}");
            }
        }
        put(name, baos.toByteArray());
    }

    private File address(String name) throws UnsupportedEncodingException {
        return new File(base, addresser(name));
    }

    public void put(String name, URL u, TestOutput progress) throws IOException {
        URLConnection c = u.openConnection();
        if (u.getProtocol().equals("http") || u.getProtocol().equals("https")) {
            // TODO do we want to remove http and simply fetch the http version?
            HttpURLConnection huc = (HttpURLConnection) c;
            huc.setIfModifiedSince(address(name).lastModified());
            if (huc.getResponseCode() == 301) {
                put(name, new URL(huc.getHeaderField("Location")), progress);
                return;
            }
            if (huc.getResponseCode() == 304)
                return;
            if (huc.getResponseCode() == 404)
                return;
        }
        System.out.println("Fetching URL to cache: " + u);
        int len = 0;
        try {
            String hf = c.getHeaderField("Content-length");
            if (hf != null) {
                len = Integer.parseInt(hf);
            }
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        put(name, c.getInputStream(), progress, len);
        System.out.println("Fetched URL to cache: " + u);
    }

}
