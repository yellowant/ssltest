package de.dogcraft.ssltest.tasks;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.Certificate;

import de.dogcraft.ssltest.executor.TaskQueue;
import de.dogcraft.ssltest.executor.TaskQueue.Task;
import de.dogcraft.ssltest.tests.CertificateTest;
import de.dogcraft.ssltest.tests.TestOutput;

public class CertificateChecker extends Task {

    private final Certificate cert;

    TestOutput out;

    public CertificateChecker(TaskQueue q, Certificate cert, TestOutput out) {
        q.super();

        this.cert = cert;
        this.out = out;
        requeue();
    }

    @Override
    public void run() {
    }

    public class ValidityChecker extends Task {

        public ValidityChecker() {
            CertificateChecker.this.getQueue().super();
        }

        @Override
        public void run() {

        }

    }

    public class CRLValidityChecker extends ValidityChecker {

        @Override
        public void run() {

        }

    }

    public class OCSPValidityChecker extends ValidityChecker {

        @Override
        public void run() {

        }

    }

}
