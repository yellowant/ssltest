package de.dogcraft.ssltest;

import java.io.PrintStream;

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
