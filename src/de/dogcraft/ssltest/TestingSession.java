package de.dogcraft.ssltest;

import java.io.PrintStream;
import java.util.LinkedList;
import java.util.ListIterator;

public class TestingSession extends TestOutput {
	String host;
	int port;
	StringBuffer strb = new StringBuffer();
	public TestingSession() {
	}
	LinkedList<PrintStream> interestedParties = new LinkedList<>();
	public synchronized void attach(PrintStream target) {
		target.print(strb.toString());
		target.flush();
		if (!ended) {
			interestedParties.add(target);
		}
	}
	@Override
	public synchronized void println(String s) {
		strb.append(s);
		strb.append('\n');
		ListIterator<PrintStream> it = interestedParties.listIterator();
		while (it.hasNext()) {
			PrintStream ps = it.next();
			if (ps.checkError()) {
				it.remove();
				continue;
			}
			ps.println(s);
		}
	}
	boolean ended;
	@Override
	public void end() {
		super.end();
		ended = true;
		synchronized (this) {
			notifyAll();
		}
	}
	public synchronized void waitForCompletion() {
		while (!ended) {
			try {
				wait();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

}
