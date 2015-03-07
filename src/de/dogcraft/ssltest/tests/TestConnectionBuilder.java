package de.dogcraft.ssltest.tests;

import java.io.IOException;
import java.net.Socket;

public interface TestConnectionBuilder {

    public Socket spawn() throws IOException;
}
