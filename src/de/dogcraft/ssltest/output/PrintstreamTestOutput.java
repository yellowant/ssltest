package de.dogcraft.ssltest.output;

import java.io.PrintStream;

import de.dogcraft.ssltest.tests.TestOutput;

public class PrintstreamTestOutput extends TestOutput {

    private PrintStream ps;

    public PrintstreamTestOutput(PrintStream ps) {
        this.ps = ps;
    }

    @Override
    public void println(String s) {
        ps.println(s);
    }

}
