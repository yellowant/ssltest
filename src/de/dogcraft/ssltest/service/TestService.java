package de.dogcraft.ssltest.service;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class TestService {

    public void performTest(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        if (useEventStream) {
            resp.setContentType("text/event-stream");
        } else {
            resp.setContentType("text/plain");
        }
    }

}
