package org.bouncycastle.crypto.tls;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class CipherConstants {

    public enum Kex {
        NULL, RSA_EXPORT(false, true), RSA, //
        DH, DHE(true), DH_anon(true), DH_EXPORT(false, true), DHE_EXPORT(true, true),//
        ECDH, ECDHE(true),//
        PSK, RSA_PSK, SRP_SHA;

        private final boolean pfs;

        private final boolean export;

        private Kex() {
            this(false, false);
        }

        private Kex(boolean pfs) {
            this(pfs, false);
        }

        private Kex(boolean pfs, boolean export) {
            this.pfs = pfs;
            this.export = export;

        }

        public boolean isPfs() {
            return pfs;
        }

        public boolean isExport() {
            return export;
        }

        public String getType() {
            String s = toString();
            if (s.endsWith("_EXPORT")) {
                s = s.substring(0, s.length() - 7);
            }
            if (s.endsWith("DHE")) {
                s = s.substring(0, s.length() - 1);
            }
            return s;
        }
    }

    public enum Auth {
        NULL, RSA, DSS, PSK, ECDH, ECDSA
    }

    public enum OperationMode {
        Stream, CBC, GCM, Unknown
    }

    public enum Enc {
        NULL( -1, -1, "NULL", OperationMode.Unknown),//
        RC4_128(128, 0, "RC4", OperationMode.Stream), RC4_40(40, 0, "RC4", OperationMode.Stream),//
        RC2_CBC_40(40, 0, "RC2", OperationMode.CBC),//
        IDEA_CBC(128, 64, "IDEA", OperationMode.CBC),//
        DES_CBC(56, 64, "DES", OperationMode.CBC), DES40_CBC(40, 64, "DES", OperationMode.CBC), _3DES_EDE_CBC(168, 64, "3DES_EDE", OperationMode.CBC),//
        AES_128_CBC(128, 128, "AES", OperationMode.CBC), AES_256_CBC(256, 128, "AES", OperationMode.CBC), AES_128_GCM(128, 128, "AES", OperationMode.GCM), AES_256_GCM(256, 128, "AES", OperationMode.GCM),//
        CAMELLIA_128_CBC(128, 128, "CAMELLIA", OperationMode.CBC), CAMELLIA_256_CBC(256, 128, "CAMELLIA", OperationMode.CBC), CAMELLIA_128_GCM(128, 128, "CAMELLIA", OperationMode.GCM), CAMELLIA_256_GCM(256, 128, "CAMELLIA", OperationMode.GCM),//
        SEED_CBC(128, 128, "SEED", OperationMode.CBC), CHACHA20(256, 0, "CHACHA20", OperationMode.Stream);

        private final int ksize;

        private final int bsize;

        private final String type;

        private final OperationMode mode;

        private Enc(int ksize, int bsize, String type, OperationMode mode) {
            this.ksize = ksize;
            this.bsize = bsize;
            this.type = type;
            this.mode = mode;
        }

        public int getBsize() {
            return bsize;
        }

        public int getKsize() {
            return ksize;
        }

        public String getType() {
            return type;
        }

        public OperationMode getCipherMode() {
            return mode;
        }

    }

    public enum Mac {
        NULL( -1, "NULL"), MD5(128, "MD5"), SHA(160, "SHA1"), SHA256(256, "SHA2"), SHA384(384, "SHA2");

        private final int dgst;

        private String type;

        private Mac(int dgst, String type) {
            this.dgst = dgst;
            this.type = type;
        }

        public int getDgst() {
            return dgst;
        }

        public String getType() {
            return type;
        }
    }

    public enum CipherSuite {

        TLS_NULL_WITH_NULL_NULL(0x0000, Kex.NULL, Auth.NULL, Enc.NULL, Mac.NULL), //
        TLS_RSA_WITH_NULL_MD5(0x0001, Kex.RSA, Auth.RSA, Enc.NULL, Mac.MD5),//
        TLS_RSA_WITH_NULL_SHA(0x0002, Kex.RSA, Auth.RSA, Enc.NULL, Mac.SHA),//
        TLS_RSA_EXPORT_WITH_RC4_40_MD5(0x0003, Kex.RSA_EXPORT, Auth.RSA, Enc.RC4_40, Mac.MD5),//
        TLS_RSA_WITH_RC4_128_MD5(0x0004, Kex.RSA, Auth.RSA, Enc.RC4_128, Mac.MD5),//
        TLS_RSA_WITH_RC4_128_SHA(0x0005, Kex.RSA, Auth.RSA, Enc.RC4_128, Mac.SHA),//
        TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5(0x0006, Kex.RSA_EXPORT, Auth.RSA, Enc.RC2_CBC_40, Mac.MD5),//
        TLS_RSA_WITH_IDEA_CBC_SHA(0x0007, Kex.RSA, Auth.RSA, Enc.IDEA_CBC, Mac.SHA),//
        TLS_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0008, Kex.RSA_EXPORT, Auth.RSA, Enc.DES40_CBC, Mac.SHA),//
        TLS_RSA_WITH_DES_CBC_SHA(0x0009, Kex.RSA, Auth.RSA, Enc.DES_CBC, Mac.SHA),//
        TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000A, Kex.RSA, Auth.RSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA(0x000B, Kex.DH_EXPORT, Auth.DSS, Enc.DES40_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_DES_CBC_SHA(0x000C, Kex.DH, Auth.DSS, Enc.DES_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x000D, Kex.DH, Auth.DSS, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA(0x000E, Kex.DH_EXPORT, Auth.RSA, Enc.DES40_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_DES_CBC_SHA(0x000F, Kex.DH, Auth.RSA, Enc.DES_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x0010, Kex.DH, Auth.RSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA(0x0011, Kex.DHE_EXPORT, Auth.DSS, Enc.DES40_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_DES_CBC_SHA(0x0012, Kex.DHE, Auth.DSS, Enc.DES_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x0013, Kex.DHE, Auth.DSS, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0014, Kex.DHE_EXPORT, Auth.RSA, Enc.DES40_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_DES_CBC_SHA(0x0015, Kex.DHE, Auth.RSA, Enc.DES_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016, Kex.DHE, Auth.RSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_DH_anon_EXPORT_WITH_RC4_40_MD5(0x0017, Kex.DH_EXPORT, Auth.NULL, Enc.RC4_40, Mac.MD5),//
        TLS_DH_anon_WITH_RC4_128_MD5(0x0018, Kex.DH, Auth.NULL, Enc.RC4_128, Mac.MD5),//
        TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA(0x0019, Kex.DH_EXPORT, Auth.NULL, Enc.DES40_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_DES_CBC_SHA(0x001A, Kex.DH, Auth.NULL, Enc.DES_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(0x001B, Kex.DH, Auth.NULL, Enc._3DES_EDE_CBC, Mac.SHA),//

        /*
         * Note: The cipher suite values { 0x00, 0x1C } and { 0x00, 0x1D } are
         * reserved to avoid collision with Fortezza-based cipher suites in SSL
         * 3.
         */

        /*
         * RFC 3268
         */

        TLS_RSA_WITH_AES_128_CBC_SHA(0x002F, Kex.RSA, Auth.RSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x0030, Kex.DH, Auth.DSS, Enc.AES_128_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x0031, Kex.DH, Auth.RSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032, Kex.DHE, Auth.DSS, Enc.AES_128_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033, Kex.DHE, Auth.RSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_AES_128_CBC_SHA(0x0034, Kex.DH, Auth.NULL, Enc.AES_128_CBC, Mac.SHA),//
        TLS_RSA_WITH_AES_256_CBC_SHA(0x0035, Kex.RSA, Auth.RSA, Enc.AES_256_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x0036, Kex.DH, Auth.DSS, Enc.AES_256_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x0037, Kex.DH, Auth.RSA, Enc.AES_256_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038, Kex.DHE, Auth.DSS, Enc.AES_256_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039, Kex.DHE, Auth.RSA, Enc.AES_256_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_AES_256_CBC_SHA(0x003A, Kex.DH, Auth.NULL, Enc.AES_256_CBC, Mac.SHA),//
        /*
         * RFC 5932
         */
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041, Kex.RSA, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0042, Kex.DH, Auth.DSS, Enc.CAMELLIA_128_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0043, Kex.DH, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0044, Kex.DHE, Auth.DSS, Enc.CAMELLIA_128_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045, Kex.DHE, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA(0x0046, Kex.DH, Auth.NULL, Enc.CAMELLIA_128_CBC, Mac.SHA),//
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084, Kex.RSA, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0085, Kex.DH, Auth.DSS, Enc.CAMELLIA_256_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0086, Kex.DH, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0087, Kex.DHE, Auth.DSS, Enc.CAMELLIA_256_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088, Kex.DHE, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA(0x0089, Kex.DH, Auth.NULL, Enc.CAMELLIA_256_CBC, Mac.SHA),//
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BA, Kex.RSA, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BB, Kex.DH, Auth.DSS, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BC, Kex.DH, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BD, Kex.DHE, Auth.DSS, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BE, Kex.DHE, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256(0x00BF, Kex.DH, Auth.NULL, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C0, Kex.RSA, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA256),//
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C1, Kex.DH, Auth.DSS, Enc.CAMELLIA_256_CBC, Mac.SHA256),//
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C2, Kex.DH, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA256),//
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C3, Kex.DHE, Auth.DSS, Enc.CAMELLIA_256_CBC, Mac.SHA256),//
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C4, Kex.DHE, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA256),//
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256(0x00C5, Kex.DH, Auth.NULL, Enc.CAMELLIA_256_CBC, Mac.SHA256),//
        /*
         * RFC 4162
         */
        TLS_RSA_WITH_SEED_CBC_SHA(0x0096, Kex.RSA, Auth.RSA, Enc.SEED_CBC, Mac.SHA),//
        TLS_DH_DSS_WITH_SEED_CBC_SHA(0x0097, Kex.DH, Auth.DSS, Enc.SEED_CBC, Mac.SHA),//
        TLS_DH_RSA_WITH_SEED_CBC_SHA(0x0098, Kex.DH, Auth.RSA, Enc.SEED_CBC, Mac.SHA),//
        TLS_DHE_DSS_WITH_SEED_CBC_SHA(0x0099, Kex.DHE, Auth.DSS, Enc.SEED_CBC, Mac.SHA),//
        TLS_DHE_RSA_WITH_SEED_CBC_SHA(0x009A, Kex.DHE, Auth.RSA, Enc.SEED_CBC, Mac.SHA),//
        TLS_DH_anon_WITH_SEED_CBC_SHA(0x009B, Kex.DH, Auth.NULL, Enc.SEED_CBC, Mac.SHA),//
        /*
         * RFC 4279
         */
        TLS_PSK_WITH_RC4_128_SHA(0x008A, Kex.PSK, Auth.PSK, Enc.RC4_128, Mac.SHA),//
        TLS_PSK_WITH_3DES_EDE_CBC_SHA(0x008B, Kex.PSK, Auth.PSK, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_PSK_WITH_AES_128_CBC_SHA(0x008C, Kex.PSK, Auth.PSK, Enc.AES_128_CBC, Mac.SHA),//
        TLS_PSK_WITH_AES_256_CBC_SHA(0x008D, Kex.PSK, Auth.PSK, Enc.AES_256_CBC, Mac.SHA),//
        TLS_DHE_PSK_WITH_RC4_128_SHA(0x008E, Kex.DHE, Auth.PSK, Enc.RC4_128, Mac.SHA),//
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(0x008F, Kex.DHE, Auth.PSK, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA(0x0090, Kex.DHE, Auth.PSK, Enc.AES_128_CBC, Mac.SHA),//
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA(0x0091, Kex.DHE, Auth.PSK, Enc.AES_256_CBC, Mac.SHA),//
        TLS_RSA_PSK_WITH_RC4_128_SHA(0x0092, Kex.RSA_PSK, Auth.RSA, Enc.RC4_128, Mac.SHA),//
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(0x0093, Kex.RSA_PSK, Auth.RSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA(0x0094, Kex.RSA_PSK, Auth.RSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA(0x0095, Kex.RSA_PSK, Auth.RSA, Enc.AES_256_CBC, Mac.SHA),//
        /*
         * RFC 4492
         */
        TLS_ECDH_ECDSA_WITH_NULL_SHA(0xC001, Kex.ECDH, Auth.ECDH, Enc.NULL, Mac.SHA),//
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0xC002, Kex.ECDH, Auth.ECDH, Enc.RC4_128, Mac.SHA),//
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC003, Kex.ECDH, Auth.ECDH, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004, Kex.ECDH, Auth.ECDH, Enc.AES_128_CBC, Mac.SHA),//
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005, Kex.ECDH, Auth.ECDH, Enc.AES_256_CBC, Mac.SHA),//
        TLS_ECDHE_ECDSA_WITH_NULL_SHA(0xC006, Kex.ECDHE, Auth.ECDSA, Enc.NULL, Mac.SHA),//
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xC007, Kex.ECDHE, Auth.ECDSA, Enc.RC4_128, Mac.SHA),//
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC008, Kex.ECDHE, Auth.ECDSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009, Kex.ECDHE, Auth.ECDSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A, Kex.ECDHE, Auth.ECDSA, Enc.AES_256_CBC, Mac.SHA),//
        TLS_ECDH_RSA_WITH_NULL_SHA(0xC00B, Kex.ECDH, Auth.ECDH, Enc.NULL, Mac.SHA),//
        TLS_ECDH_RSA_WITH_RC4_128_SHA(0xC00C, Kex.ECDH, Auth.ECDH, Enc.RC4_128, Mac.SHA),//
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(0xC00D, Kex.ECDH, Auth.ECDH, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E, Kex.ECDH, Auth.ECDH, Enc.AES_128_CBC, Mac.SHA),//
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F, Kex.ECDH, Auth.ECDH, Enc.AES_256_CBC, Mac.SHA),//
        TLS_ECDHE_RSA_WITH_NULL_SHA(0xC010, Kex.ECDHE, Auth.RSA, Enc.NULL, Mac.SHA),//
        TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xC011, Kex.ECDHE, Auth.RSA, Enc.RC4_128, Mac.SHA),//
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xC012, Kex.ECDHE, Auth.RSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013, Kex.ECDHE, Auth.RSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014, Kex.ECDHE, Auth.RSA, Enc.AES_256_CBC, Mac.SHA),//
        TLS_ECDH_anon_WITH_NULL_SHA(0xC015, Kex.ECDH, Auth.ECDH, Enc.NULL, Mac.SHA),//
        TLS_ECDH_anon_WITH_RC4_128_SHA(0xC016, Kex.ECDH, Auth.ECDH, Enc.RC4_128, Mac.SHA),//
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0xC017, Kex.ECDH, Auth.ECDH, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xC018, Kex.ECDH, Auth.ECDH, Enc.AES_128_CBC, Mac.SHA),//
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xC019, Kex.ECDH, Auth.ECDH, Enc.AES_256_CBC, Mac.SHA),//
        /*
         * RFC 4785
         */
        TLS_PSK_WITH_NULL_SHA(0x002C, Kex.PSK, Auth.PSK, Enc.NULL, Mac.SHA),//
        TLS_DHE_PSK_WITH_NULL_SHA(0x002D, Kex.DHE, Auth.PSK, Enc.NULL, Mac.SHA),//
        TLS_RSA_PSK_WITH_NULL_SHA(0x002E, Kex.RSA_PSK, Auth.RSA, Enc.NULL, Mac.SHA),//
        /*
         * RFC 5054
         */
        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(0xC01A, Kex.SRP_SHA, null, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(0xC01B, Kex.SRP_SHA, Auth.RSA, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(0xC01C, Kex.SRP_SHA, Auth.DSS, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA(0xC01D, Kex.SRP_SHA, null, Enc.AES_128_CBC, Mac.SHA),//
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(0xC01E, Kex.SRP_SHA, Auth.RSA, Enc.AES_128_CBC, Mac.SHA),//
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(0xC01F, Kex.SRP_SHA, Auth.DSS, Enc.AES_128_CBC, Mac.SHA),//
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA(0xC020, Kex.SRP_SHA, null, Enc.AES_256_CBC, Mac.SHA),//
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(0xC021, Kex.SRP_SHA, Auth.RSA, Enc.AES_256_CBC, Mac.SHA),//
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(0xC022, Kex.SRP_SHA, Auth.DSS, Enc.AES_256_CBC, Mac.SHA),//
        /*
         * RFC 5246
         */
        TLS_RSA_WITH_NULL_SHA256(0x003B, Kex.RSA, Auth.RSA, Enc.NULL, Mac.SHA256),//
        TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C, Kex.RSA, Auth.RSA, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D, Kex.RSA, Auth.RSA, Enc.AES_256_CBC, Mac.SHA256),//
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x003E, Kex.DH, Auth.DSS, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x003F, Kex.DH, Auth.RSA, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040, Kex.DHE, Auth.DSS, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067, Kex.DHE, Auth.RSA, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x0068, Kex.DH, Auth.DSS, Enc.AES_256_CBC, Mac.SHA256),//
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x0069, Kex.DH, Auth.RSA, Enc.AES_256_CBC, Mac.SHA256),//
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A, Kex.DHE, Auth.DSS, Enc.AES_256_CBC, Mac.SHA256),//
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B, Kex.DHE, Auth.RSA, Enc.AES_256_CBC, Mac.SHA256),//
        TLS_DH_anon_WITH_AES_128_CBC_SHA256(0x006C, Kex.DH, Auth.NULL, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_DH_anon_WITH_AES_256_CBC_SHA256(0x006D, Kex.DH, Auth.NULL, Enc.AES_256_CBC, Mac.SHA256),//
        /*
         * RFC 5288
         */
        TLS_RSA_WITH_AES_128_GCM_SHA256(0x009C, Kex.RSA, Auth.RSA, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_RSA_WITH_AES_256_GCM_SHA384(0x009D, Kex.RSA, Auth.RSA, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009E, Kex.DHE, Auth.RSA, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009F, Kex.DHE, Auth.RSA, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256(0x00A0, Kex.DH, Auth.RSA, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384(0x00A1, Kex.DH, Auth.RSA, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00A2, Kex.DHE, Auth.DSS, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00A3, Kex.DHE, Auth.DSS, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256(0x00A4, Kex.DH, Auth.DSS, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384(0x00A5, Kex.DH, Auth.DSS, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_DH_anon_WITH_AES_128_GCM_SHA256(0x00A6, Kex.DH, Auth.NULL, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_DH_anon_WITH_AES_256_GCM_SHA384(0x00A7, Kex.DH, Auth.NULL, Enc.AES_256_GCM, Mac.SHA384),//
        /*
         * RFC 5289
         */
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023, Kex.ECDHE, Auth.ECDSA, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024, Kex.ECDHE, Auth.ECDSA, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025, Kex.ECDH, Auth.ECDH, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026, Kex.ECDH, Auth.ECDH, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027, Kex.ECDHE, Auth.RSA, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028, Kex.ECDHE, Auth.RSA, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029, Kex.ECDH, Auth.ECDH, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A, Kex.ECDH, Auth.ECDH, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B, Kex.ECDHE, Auth.ECDSA, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C, Kex.ECDHE, Auth.ECDSA, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D, Kex.ECDH, Auth.ECDH, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E, Kex.ECDH, Auth.ECDH, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F, Kex.ECDHE, Auth.RSA, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030, Kex.ECDHE, Auth.RSA, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031, Kex.ECDH, Auth.ECDH, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032, Kex.ECDH, Auth.ECDH, Enc.AES_256_GCM, Mac.SHA384),//
        /*
         * RFC 5487
         */
        TLS_PSK_WITH_AES_128_GCM_SHA256(0x00A8, Kex.PSK, Auth.PSK, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_PSK_WITH_AES_256_GCM_SHA384(0x00A9, Kex.PSK, Auth.PSK, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(0x00AA, Kex.DHE, Auth.PSK, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(0x00AB, Kex.DHE, Auth.PSK, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(0x00AC, Kex.RSA_PSK, Auth.RSA, Enc.AES_128_GCM, Mac.SHA256),//
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(0x00AD, Kex.RSA_PSK, Auth.RSA, Enc.AES_256_GCM, Mac.SHA384),//
        TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE, Kex.PSK, Auth.PSK, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_PSK_WITH_AES_256_CBC_SHA384(0x00AF, Kex.PSK, Auth.PSK, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_PSK_WITH_NULL_SHA256(0x00B0, Kex.PSK, Auth.PSK, Enc.NULL, Mac.SHA256),//
        TLS_PSK_WITH_NULL_SHA384(0x00B1, Kex.PSK, Auth.PSK, Enc.NULL, Mac.SHA384),//
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(0x00B2, Kex.DHE, Auth.PSK, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(0x00B3, Kex.DHE, Auth.PSK, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_DHE_PSK_WITH_NULL_SHA256(0x00B4, Kex.DHE, Auth.PSK, Enc.NULL, Mac.SHA256),//
        TLS_DHE_PSK_WITH_NULL_SHA384(0x00B5, Kex.DHE, Auth.PSK, Enc.NULL, Mac.SHA384),//
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(0x00B6, Kex.RSA_PSK, Auth.RSA, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(0x00B7, Kex.RSA_PSK, Auth.RSA, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_RSA_PSK_WITH_NULL_SHA256(0x00B8, Kex.RSA_PSK, Auth.RSA, Enc.NULL, Mac.SHA256),//
        TLS_RSA_PSK_WITH_NULL_SHA384(0x00B9, Kex.RSA_PSK, Auth.RSA, Enc.NULL, Mac.SHA384),//
        /*
         * RFC 5489
         */
        TLS_ECDHE_PSK_WITH_RC4_128_SHA(0xC033, Kex.ECDHE, Auth.PSK, Enc.RC4_128, Mac.SHA),//
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(0xC034, Kex.ECDHE, Auth.PSK, Enc._3DES_EDE_CBC, Mac.SHA),//
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(0xC035, Kex.ECDHE, Auth.PSK, Enc.AES_128_CBC, Mac.SHA),//
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(0xC036, Kex.ECDHE, Auth.PSK, Enc.AES_256_CBC, Mac.SHA),//
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(0xC037, Kex.ECDHE, Auth.PSK, Enc.AES_128_CBC, Mac.SHA256),//
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(0xC038, Kex.ECDHE, Auth.PSK, Enc.AES_256_CBC, Mac.SHA384),//
        TLS_ECDHE_PSK_WITH_NULL_SHA(0xC039, Kex.ECDHE, Auth.PSK, Enc.NULL, Mac.SHA),//
        TLS_ECDHE_PSK_WITH_NULL_SHA256(0xC03A, Kex.ECDHE, Auth.PSK, Enc.NULL, Mac.SHA256),//
        TLS_ECDHE_PSK_WITH_NULL_SHA384(0xC03B, Kex.ECDHE, Auth.PSK, Enc.NULL, Mac.SHA384),//
        /*
         * RFC 5746
         */
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF, null, null, null, null),//
        /*
         * RFC 6367
         */
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC072, Kex.ECDHE, Auth.ECDSA, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC073, Kex.ECDHE, Auth.ECDSA, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC074, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC075, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC076, Kex.ECDHE, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC077, Kex.ECDHE, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC078, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC079, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07A, Kex.RSA, Auth.RSA, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07B, Kex.RSA, Auth.RSA, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07C, Kex.DHE, Auth.RSA, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07D, Kex.DHE, Auth.RSA, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07E, Kex.DH, Auth.RSA, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07F, Kex.DH, Auth.RSA, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC080, Kex.DHE, Auth.DSS, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC081, Kex.DHE, Auth.DSS, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC082, Kex.DH, Auth.DSS, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC083, Kex.DH, Auth.DSS, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256(0xC084, Kex.DH, Auth.NULL, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384(0xC085, Kex.DH, Auth.NULL, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC086, Kex.ECDHE, Auth.ECDSA, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC087, Kex.ECDHE, Auth.ECDSA, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC088, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC089, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08A, Kex.ECDHE, Auth.RSA, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08B, Kex.ECDHE, Auth.RSA, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08C, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08D, Kex.ECDH, Auth.ECDH, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC08E, Kex.PSK, Auth.PSK, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC08F, Kex.PSK, Auth.PSK, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC090, Kex.DHE, Auth.PSK, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC091, Kex.DHE, Auth.PSK, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC092, Kex.RSA_PSK, Auth.RSA, Enc.CAMELLIA_128_GCM, Mac.SHA256),//
        TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC093, Kex.RSA_PSK, Auth.RSA, Enc.CAMELLIA_256_GCM, Mac.SHA384),//
        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC094, Kex.PSK, Auth.PSK, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC095, Kex.PSK, Auth.PSK, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC096, Kex.DHE, Auth.PSK, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC097, Kex.DHE, Auth.PSK, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC098, Kex.RSA_PSK, Auth.RSA, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC099, Kex.RSA_PSK, Auth.RSA, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC09A, Kex.ECDHE, Auth.PSK, Enc.CAMELLIA_128_CBC, Mac.SHA256),//
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC09B, Kex.ECDHE, Auth.PSK, Enc.CAMELLIA_256_CBC, Mac.SHA384),//
        /*
         * RFC 6655
         */
        TLS_RSA_WITH_AES_128_CCM(0xC09C, Kex.RSA, Auth.RSA, null, null),//
        TLS_RSA_WITH_AES_256_CCM(0xC09D, Kex.RSA, Auth.RSA, null, null),//
        TLS_DHE_RSA_WITH_AES_128_CCM(0xC09E, Kex.DHE, Auth.RSA, null, null),//
        TLS_DHE_RSA_WITH_AES_256_CCM(0xC09F, Kex.DHE, Auth.RSA, null, null),//
        TLS_RSA_WITH_AES_128_CCM_8(0xC0A0, Kex.RSA, Auth.RSA, null, null),//
        TLS_RSA_WITH_AES_256_CCM_8(0xC0A1, Kex.RSA, Auth.RSA, null, null),//
        TLS_DHE_RSA_WITH_AES_128_CCM_8(0xC0A2, Kex.DHE, Auth.RSA, null, null),//
        TLS_DHE_RSA_WITH_AES_256_CCM_8(0xC0A3, Kex.DHE, Auth.RSA, null, null),//
        TLS_PSK_WITH_AES_128_CCM(0xC0A4, Kex.PSK, Auth.PSK, null, null),//
        TLS_PSK_WITH_AES_256_CCM(0xC0A5, Kex.PSK, Auth.PSK, null, null),//
        TLS_DHE_PSK_WITH_AES_128_CCM(0xC0A6, Kex.DHE, Auth.PSK, null, null),//
        TLS_DHE_PSK_WITH_AES_256_CCM(0xC0A7, Kex.DHE, Auth.PSK, null, null),//
        TLS_PSK_WITH_AES_128_CCM_8(0xC0A8, Kex.PSK, Auth.PSK, null, null),//
        TLS_PSK_WITH_AES_256_CCM_8(0xC0A9, Kex.PSK, Auth.PSK, null, null),//
        TLS_DHE_PSK_WITH_AES_128_CCM_8(0xC0AA, Kex.DHE, Auth.PSK, null, null),//
        TLS_DHE_PSK_WITH_AES_256_CCM_8(0xC0AB, Kex.DHE, Auth.PSK, null, null),//
        /*
         * draft-agl-tls-chacha20poly1305-04
         */
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCC13, Kex.ECDHE, Auth.RSA, Enc.CHACHA20, Mac.SHA256),//
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCC14, Kex.ECDHE, Auth.ECDSA, Enc.CHACHA20, Mac.SHA256),//
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCC15, Kex.DHE, Auth.RSA, Enc.CHACHA20, Mac.SHA256),//
        /*
         * draft-josefsson-salsa20-tls-04
         */
        TLS_RSA_WITH_ESTREAM_SALSA20_SHA1(0xE410, Kex.RSA, Auth.RSA, null, null),//
        TLS_RSA_WITH_SALSA20_SHA1(0xE411, Kex.RSA, Auth.RSA, null, null),//
        TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1(0xE412, Kex.ECDHE, Auth.RSA, null, null),//
        TLS_ECDHE_RSA_WITH_SALSA20_SHA1(0xE413, Kex.ECDHE, Auth.RSA, null, null),//
        TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1(0xE414, Kex.ECDHE, Auth.ECDSA, null, null),//
        TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1(0xE415, Kex.ECDHE, Auth.ECDSA, null, null),//
        TLS_PSK_WITH_ESTREAM_SALSA20_SHA1(0xE416, Kex.PSK, Auth.PSK, null, null),//
        TLS_PSK_WITH_SALSA20_SHA1(0xE417, Kex.PSK, Auth.PSK, null, null),//
        TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1(0xE418, Kex.ECDHE, Auth.PSK, null, null),//
        TLS_ECDHE_PSK_WITH_SALSA20_SHA1(0xE419, Kex.ECDHE, Auth.PSK, null, null),//
        TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1(0xE41A, Kex.RSA_PSK, Auth.RSA, null, null),//
        TLS_RSA_PSK_WITH_SALSA20_SHA1(0xE41B, Kex.RSA_PSK, Auth.RSA, null, null),//
        TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1(0xE41C, Kex.DHE, Auth.PSK, null, null),//
        TLS_DHE_PSK_WITH_SALSA20_SHA1(0xE41D, Kex.DHE, Auth.PSK, null, null),//
        TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1(0xE41E, Kex.DHE, Auth.RSA, null, null),//
        TLS_DHE_RSA_WITH_SALSA20_SHA1(0xE41F, Kex.DHE, Auth.RSA, null, null);

        private final int value;

        private final Kex kex;

        private final Auth auth;

        private final Enc enc;

        private final Mac mac;

        private CipherSuite(int value, Kex k, Auth a, Enc e, Mac m) {
            this.value = value;
            this.kex = k;
            this.auth = a;
            this.enc = e;
            this.mac = m;
        }

        public Auth getAuth() {
            return auth;
        }

        public Enc getEnc() {
            return enc;
        }

        public Kex getKex() {
            return kex;
        }

        public Mac getMac() {
            return mac;
        }

        public int getValue() {
            return value;
        }

    }

    private static final Map<Integer, CipherSuite> ciphers;
    static {
        HashMap<Integer, CipherSuite> index = new HashMap<>();
        for (CipherSuite c : CipherSuite.values()) {
            index.put(c.getValue(), c);
        }
        ciphers = Collections.unmodifiableMap(index);
    }

    public static CipherSuite getById(int id) {
        return ciphers.get(id);
    }
}
