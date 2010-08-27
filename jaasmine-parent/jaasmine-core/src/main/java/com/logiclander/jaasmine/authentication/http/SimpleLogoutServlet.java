/*
 * Copyright 2010 LogicLander
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.logiclander.jaasmine.authentication.http;

import com.logiclander.jaasmine.authentication.AuthenticationService;
import com.logiclander.jaasmine.authentication.SimpleAuthenticationService;
import java.io.IOException;
import java.io.PrintWriter;
import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author agherna
 */
public class SimpleLogoutServlet extends HttpServlet {

    private final Log logger = LogFactory.getLog(SimpleLogoutServlet.class);

    private String appName;

    private String postLogoutProcessorName;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        HttpSession sess = req.getSession();
        Subject subj =
            (Subject) sess.getAttribute(AuthenticationService.SUBJECT_KEY);

        if (subj == null) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        // Log out the Subject
        AuthenticationService as = new SimpleAuthenticationService(appName);
        as.logout(subj);

        // Invalidate the session
        sess.invalidate();

        resp.setStatus(HttpServletResponse.SC_OK);
        RequestDispatcher rd = 
            getServletContext().getNamedDispatcher(postLogoutProcessorName);

        if (rd != null) {
            resp.setContentType("text/html");
            rd.include(req, resp);
        } else {
            sendPlainTextResponse(req, resp);
        }

    }


    private void sendPlainTextResponse(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException {

        resp.setContentType("text/plain");
        PrintWriter w = resp.getWriter();
        w.println("You have been logged out");

        w.flush();
    }

    
    @Override
    public void init() throws ServletException {

        appName = getInitParameter("appName");
        if (appName == null || appName.isEmpty()) {
            appName = AuthenticationService.DEFAULT_JAAS_SPNEGO_CONFIG;
        }

        postLogoutProcessorName = getInitParameter("postLogoutProcessorName");
        if (postLogoutProcessorName == null ||
                postLogoutProcessorName.isEmpty()) {
            postLogoutProcessorName = "SimplePostLogoutProcessorServlet";
        }

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s initialized", toString()));
        }

    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SimpleLogoutServlet other = (SimpleLogoutServlet) obj;
        if ((this.appName == null) ? (other.appName != null) :
            !this.appName.equals(other.appName)) {
            return false;
        }
        return true;
    }


    @Override
    public int hashCode() {
        int hash = 7;
        hash = 17 * hash + (this.appName != null ? this.appName.hashCode() : 0);
        return hash;
    }


    @Override
    public String toString() {
        return String.format("%s for %s", this.getClass().getSimpleName(),
                appName);
    }


}
