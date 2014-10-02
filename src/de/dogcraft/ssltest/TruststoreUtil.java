package de.dogcraft.ssltest;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

public class TruststoreUtil {
	private static void readPems(String pem, String store) throws IOException,
			InterruptedException {
		BufferedReader br = new BufferedReader(new FileReader(new File(pem)));
		String s;
		boolean cert = false;
		Process keytool = null;
		PrintStream out = null;
		int c = 1;
		while ((s = br.readLine()) != null) {
			if (s.startsWith("-----BEGIN CERTIFICATE--")) {
				cert = true;
			}
			if (cert) {
				if (out == null) {
					keytool = Runtime.getRuntime().exec(
							new String[]{"keytool", "-importcert", "-keystore",
									store, "-storepass", "changeit",
									"-noprompt", "-alias", "cert-" + (c++)});
					out = new PrintStream(keytool.getOutputStream());
				}
				out.println(s);
				if (s.startsWith("-----END CERTIFICATE--")) {
					cert = false;
					out.close();
					BufferedReader err = new BufferedReader(
							new InputStreamReader(keytool.getErrorStream()));
					System.out.println(err.readLine());
					System.out.println(keytool.waitFor());

					keytool = null;
					out = null;
				}

			}
		}
		br.close();
	}
	public static void read() throws GeneralSecurityException, IOException {
		File root = new File("trusts");
		File[] data = root.listFiles(new FileFilter() {

			@Override
			public boolean accept(File pathname) {
				return pathname.getName().endsWith(".jks");
			}
		});
		for (File file : data) {
			System.out.println("======= " + file + " ==========");
			KeyStore ks = KeyStore.getInstance("jks");
			ks.load(new FileInputStream(file), "changeit".toCharArray());
			Enumeration<String> al = ks.aliases();
			while (al.hasMoreElements()) {
				String alias = al.nextElement();
				Certificate c = ks.getCertificate(alias);
				// System.out.println(alias);
				System.out.println(((X509Certificate) c).getSubjectDN());
				// outputFingerprint(c);
				System.out.println(((X509Certificate) c).getNotAfter());
				PublicKey pubk = c.getPublicKey();
				if (pubk instanceof RSAPublicKey) {
					int pub = ((RSAPublicKey) pubk).getPublicExponent()
							.intValue();
					if (pub == 3) {
						System.out.println("Bleichenbacher!!!!!!!!!");
					}
					if (((RSAPublicKey) pubk).getModulus().bitLength() <= 1024) {
						System.out.println("Small!!!!!!!!!");
					}
					String md5 = ((X509Certificate) c).getSigAlgName();
					if (md5.startsWith("MD5")) {
						System.out.println("MD5!!!!!!!!!!!");
					}
				} else {
					System.out.println("NON-RSA");
				}
			}
			System.out.println(ks.size());
		}
	}
	private static void outputFingerprint(Certificate c)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = c.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		for (byte b : digest) {
			String s = Integer.toHexString(b & 0xFF);
			if (s.length() == 1) {
				s = "0" + s;
			}
			System.out.print(s + ":");
		}
		System.out.println();
	}
	public static void main(String[] args) throws GeneralSecurityException,
			IOException, InterruptedException {
		if (args.length == 2) {
			readPems(args[0], args[1]);
			return;
		}
		read();
	}
}
