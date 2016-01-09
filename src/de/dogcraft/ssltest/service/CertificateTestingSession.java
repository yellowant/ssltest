package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import de.dogcraft.ssltest.tests.CertificateTest;
import de.dogcraft.ssltest.tests.TestOutput;
import de.dogcraft.ssltest.utils.CertificateWrapper;

public class CertificateTestingSession extends TestOutput {

    CertificateWrapper target;

    public CertificateTestingSession(CertificateWrapper target) {
        this.target = target;
    }

    private void run() {
        try {
            CertificateTest.testCerts(this, target);
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        } catch (IOException e) {
            throw new Error(e);
        }
    }

    @Override
    public void println(String s) {
        // TODO Auto-generated method stub

    }

}
