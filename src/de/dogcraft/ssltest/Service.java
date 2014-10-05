package de.dogcraft.ssltest;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.crypto.tls.Bouncy;
import org.bouncycastle.crypto.tls.ExtensionType;

public class Service extends HttpServlet {

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doGet(req, resp);
	}
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		if (req.getParameter("domain") != null) {
			stream(req, resp);
			return;
		}
		PrintWriter pw = resp.getWriter();
		pw.println("<!DOCTYPE html><html><head><title>SSL-Test</title></head><body onLoad='events()'>");
		pw.println("<form method='POST'>");
		pw.println("<input type='text' name='domain' id='domain' value='dogcraft.de'/>:<input value='443' type='text' name='port' id='port'/><input type='submit' style='display: none'></form>");
		pw.println("<script type='text/javascript'>");
		pw.println("function events(){");
		pw.println("var url = '/?event=a&domain='+encodeURIComponent(document.getElementById('domain').value)+'&port='+encodeURIComponent(document.getElementById('port').value);");
		pw.println("var jsonStream = new EventSource(url);");
		pw.println("jsonStream.onmessage = function (e) {");
		pw.println("   //var message = JSON.parse(e.data);");
		pw.println("  var text = document.createTextNode(e.data);");
		pw.println("  var ele = document.createElement(\"div\");");
		pw.println("  ele.appendChild(text)");
		pw.println("  current.appendChild(ele);");
		pw.println("};");
		pw.println("jsonStream.addEventListener(\"end\", function (e) {");
		pw.println("   jsonStream.close();jsonStream.onmessage({data:\"finished\"});");
		pw.println("});");
		pw.println("var stack = new Array();");
		pw.println("var current = document.getElementById('output'); stack.push({fs: current});");
		pw.println("jsonStream.addEventListener(\"enter\", function (e) {");
		pw.println("   var fs = document.createElement(\"fieldset\");");
		pw.println("   var legend = document.createElement(\"legend\");");
		pw.println("   var legendT = document.createTextNode(e.data);");
		pw.println("   legend.appendChild(legendT); fs.appendChild(legend);current.appendChild(fs);");
		pw.println("   stack.push({fs:fs,leg:legend, legT: legendT}); current = fs;");
		pw.println("});");
		pw.println("jsonStream.addEventListener(\"exit\", function (e) {");
		pw.println("   var frame = stack.pop(); current = stack[stack.length-1].fs;");
		pw.println("   var legT = document.createTextNode(e.data);");
		pw.println("   frame.leg.removeChild(frame.legT);");
		pw.println("   frame.leg.appendChild(legT);");
		pw.println("});");
		pw.println("jsonStream.onerror = function (){jsonStream.close();jsonStream.onmessage({data:\"error\"});}");
		pw.println("}");
		pw.println("</script><div id='output'></div></body></html>");
	}
	HashMap<String, TestingSession> cache = new HashMap<>();
	private void stream(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		if (req.getParameter("event") != null) {
			resp.setContentType("text/event-stream");
		} else {
			resp.setContentType("text/plain");
		}
		String domain = req.getParameter("domain");
		String port = req.getParameter("port");
		if (domain == null || port == null) {
			resp.sendError(500, "error params missing");
			return;
		}
		TestingSession to;
		{
			PrintStream ps = new PrintStream(resp.getOutputStream(), true);
			ps.println("retry: 10000");
			ps.println();

			String host = domain + ":" + port;
			to = cache.get(host);
			if (to == null) {
				to = new TestingSession();
				cache.put(host, to);
				to.attach(ps);
			} else {
				to.attach(ps);
				to.waitForCompletion();
			}
		}
		try {
			System.out.println("Testing " + domain + ":" + port);
			to.output("Testing " + domain + ":" + port);
			try {
				int por = Integer.parseInt(port);
				Bouncy b = new Bouncy(domain, por);
				testBugs(b, to);
				CertificateTest.testCerts(to, b);

				boolean testCompression = b.testDeflate(to);
				if (testCompression) {
					to.output("Does support tls compression. ", -10);
				} else {
					to.output("Does not support tls compression.");
				}
				to.enterTest("Determining cipher suites");
				determineCiphers(to, b);
				to.exitTest("Determining cipher suites", TestResult.IGNORE);

			} catch (NumberFormatException e) {
				to.output("error port not int");
				return;
			}
		} finally {
			to.end();
		}
	}

	private void testBugs(Bouncy b, TestOutput ps) throws IOException {
		b.testBug(ps);
		byte[] sn = (byte[]) b.getExt().get(ExtensionType.server_name);
		byte[] hb = (byte[]) b.getExt().get(ExtensionType.heartbeat);
		byte[] rn = (byte[]) b.getExt().get(ExtensionType.renegotiation_info);
		ps.output("renego: " + (rn == null ? "off" : "on"));
		ps.output("heartbeat: " + (hb == null ? "off" : "on"));
	}
	private void determineCiphers(TestOutput ps, Bouncy b) throws IOException {
		String[] ciph = b.determineCiphers(ps);
		if (b.hasServerPref()) {
			ps.output("Server has cipher preference.");
		} else {
			ps.output("Server has no cipher preference.");
		}
	}
}
