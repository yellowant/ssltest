package de.dogcraft.ssltest;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.concurrent.LinkedBlockingDeque;

public class TestOutput {
	private class TestExecution {
		String name;

		public TestExecution(String name) {
			this.name = name;
		}
		HashMap<String, TestResult> map;
		public void add(String name, TestResult tr) {
			if (TestResult.IGNORE == tr) {
				return;
			}
			if (map == null) {
				map = new HashMap<>();
			}
			map.put(name, tr);
		}
		public String getName() {
			return name;
		}
		public HashMap<String, TestResult> getMap() {
			return map;
		}
	}
	LinkedBlockingDeque<TestExecution> que = new LinkedBlockingDeque<>();
	private PrintStream ps;
	public TestOutput(PrintStream ps) {
		this.ps = ps;
		que.add(new TestExecution("root"));
	}
	public void enterTest(String testName) {
		ps.println("event: enter");
		ps.println("data: " + testName);
		ps.println();
		que.push(new TestExecution(testName));
	}
	public void exitTest(String testName, TestResult res) {
		TestExecution poll = que.poll();
		if (!poll.getName().equals(testName)) {
			throw new Error(poll.getName() + " <=> " + testName);
		}
		que.peek().add(testName, res);
		ps.println("event: exit");
		ps.println("data: " + testName
				+ (res == null ? "" : " -> " + (Math.ceil(100 * res.getRes()))));
		ps.println();

	}
	public void output(String message) {
		ps.println("data: " + message);
		ps.println();
	}
	public void finest(String message) {

	}
	public void end() {
		ps.println("event: end");
		ps.print("data: yup\n\n");
	}
	public HashMap<String, TestResult> getSubresults() {
		return que.peek().getMap();
	}
}
