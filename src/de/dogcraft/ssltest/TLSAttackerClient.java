package de.dogcraft.ssltest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;

public class TLSAttackerClient {

    static boolean gotCipher = false;

    public static void main(String[] args) {
        ArrayList<CipherSuite> ciphers = new ArrayList<CipherSuite>(Arrays.asList(CipherSuite.values()));

        do {

            GeneralConfig generalConfig = new GeneralConfig();
            generalConfig.setQuiet(false);
            generalConfig.setDebug(true);

            ClientCommandConfig clientconfig = new ClientCommandConfig();
            clientconfig.setConnect("ssltest.security.fail:443");
            clientconfig.setProtocolVersion(ProtocolVersion.TLS12);
            clientconfig.setCipherSuites(ciphers);
            clientconfig.setCompressionMethods(Arrays.asList(CompressionMethod.values()));
            clientconfig.setPointFormats(Arrays.asList(ECPointFormat.values()));
            clientconfig.setNamedCurves(Arrays.asList(NamedCurve.values()));

            Attacker<ClientCommandConfig> attacker = new Attacker<ClientCommandConfig>(clientconfig) {

                @Override
                public void executeAttack(ConfigHandler configHandler) {
                    TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
                    TlsContext tlsContext = configHandler.initializeTlsContext(config);

                    WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

                    WorkflowTrace trace = tlsContext.getWorkflowTrace();

                    try {
                        workflowExecutor.executeWorkflow();
                    } catch (WorkflowExecutionException ex) {
                        System.out.println("The TLS protocol flow was not executed completely, follow the debug messages for more information.");
                        ex.printStackTrace(System.out);
                    }

                    List<ProtocolMessage> msg = trace.getProtocolMessages();
                    for (ProtocolMessage pm : msg) {
                        ConnectionEnd pmi = pm.getMessageIssuer();
                        ProtocolMessageType pmt = pm.getProtocolMessageType();
                        System.out.print(ConnectionEnd.CLIENT.equals(pmi) ? " -> C>S:" : " <- S>C:");
                        System.out.print(pmt.toString());
                        System.out.println(":");
                        if (pm.getRecords() != null) {
                            for (Record pmr : pm.getRecords()) {
                                System.out.println(pmr.toString());
                            }
                        }
                    }

                    try {
                        ProtocolMessage pm_server_hello = trace.getFirstHandshakeMessage(HandshakeMessageType.SERVER_HELLO);
                        ProtocolMessage pm_server_keyexchange = trace.getFirstHandshakeMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE);
                        ProtocolMessage pm_server_certificate = trace.getFirstHandshakeMessage(HandshakeMessageType.CERTIFICATE);

                        ServerHelloMessage server_hello = (ServerHelloMessage) pm_server_hello;
                        ServerKeyExchangeMessage server_keyexchange = (ServerKeyExchangeMessage) pm_server_keyexchange;
                        CertificateMessage server_certificate = (CertificateMessage) pm_server_certificate;

                        CipherSuite server_cipher = CipherSuite.getCipherSuite(server_hello.getSelectedCipherSuite().getValue());

                        System.out.println(server_cipher.toString());

                        ciphers.remove(server_cipher);

                        gotCipher = true;
                    } catch (Exception e) {
                        gotCipher = false;
                    }

                    tlsContexts.add(tlsContext);

                    transportHandler.closeConnection();

                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            };

            ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(ClientCommandConfig.COMMAND);
            configHandler.initialize(generalConfig);

            attacker.executeAttack(configHandler);

        } while (gotCipher);

        System.out.println("Done!");
    }

}
