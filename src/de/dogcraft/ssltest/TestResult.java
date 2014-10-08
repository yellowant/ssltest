package de.dogcraft.ssltest;

public class TestResult {
	public static final TestResult IGNORE = null;
	public static final TestResult FAILED = new TestResult(0);
	private float res;

	public TestResult(float res) {
		this.res = res;
	}

	public float getRes() {
		return res;
	}
}
