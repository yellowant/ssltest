package de.dogcraft.ssltest.service;

import java.io.PrintStream;
import java.util.LinkedList;
import java.util.ListIterator;

import de.dogcraft.ssltest.tests.TestOutput;

public abstract class TestingSession extends TestOutput {

    private StringBuffer strb = new StringBuffer();

    private LinkedList<PrintStream> interestedParties = new LinkedList<>();

    private boolean ended;

    public synchronized void attach(PrintStream target) {
        target.print(strb.toString());
        target.flush();
        if ( !ended) {
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

    @Override
    public void end() {
        super.end();
        synchronized (this) {
            ended = true;
            notifyAll();
        }
    }

    public synchronized void waitForCompletion() {
        while ( !ended) {
            try {
                wait();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

}
