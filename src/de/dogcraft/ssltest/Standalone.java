package de.dogcraft.ssltest;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import de.dogcraft.ssltest.service.Service;
import de.dogcraft.ssltest.service.TruststoreOverview;

public class Standalone {

	public static void main(String[] args) throws Exception {
		Server s = new Server(8080);
		ServletContextHandler main = new ServletContextHandler();
		main.addServlet(new ServletHolder(new Service()), "/*");
		main.addServlet(new ServletHolder(new TruststoreOverview()), "/trust");
		HandlerList hl = new HandlerList();
		ResourceHandler hand = new ResourceHandler();
		hand.setResourceBase("static/");
		ContextHandler resHand = new ContextHandler("/static");
		resHand.setHandler(hand);
		hl.setHandlers(new Handler[] { resHand, main });
		s.setHandler(hl);
		s.start();
	}

}
