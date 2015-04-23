package de.dogcraft.ssltest.tasks;

import org.bouncycastle.asn1.x509.Certificate;

import de.dogcraft.ssltest.executor.TaskQueue;
import de.dogcraft.ssltest.executor.TaskQueue.Task;

public class CertificateChecker extends Task {

    private final Certificate cert;

    CertificateChecker(TaskQueue q, Certificate cert) {
        q.super();

        this.cert = cert;
    }

    @Override
    public void run() {

    }

    public class ValidityChecker extends Task {

        public ValidityChecker(TaskQueue q) {
            q.super();
        }

        @Override
        public void run() {

        }

    }

    public class CRLValidityChecker extends ValidityChecker {

        public CRLValidityChecker(TaskQueue q) {
            super(q);
        }

        @Override
        public void run() {

        }

    }

    public class OCSPValidityChecker extends ValidityChecker {

        public OCSPValidityChecker(TaskQueue q) {
            super(q);
        }

        @Override
        public void run() {

        }

    }

}
