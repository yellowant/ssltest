package de.dogcraft.ssltest.service;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EventSource extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        // set content type
        res.setContentType("text/event-stream");
        res.setCharacterEncoding("UTF-8");

        String msg = req.getParameter("msg");

        PrintWriter writer = res.getWriter();

        // send SSE
        writer.write("data: " + msg + "\n\n");

    }

}
