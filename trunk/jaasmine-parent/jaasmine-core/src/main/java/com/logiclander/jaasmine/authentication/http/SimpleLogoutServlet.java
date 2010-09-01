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
 * Logs out the Subject associated with the user's HttpSession.
 *
 * This filter accepts the following init-params:
 * <UL>
 *  <LI>appName - the name of the application in the JAAS configuration.  This
 * parameter is optional.  The default value is
 * {@value AuthenticationService#DEFAULT_JAAS_SPNEGO_CONFIG}</LI>
 *  <LI>postLogoutProcessorName - the name of a Servlet in the {@code web.xml}
 * file of this web application that will handle any logout post processing.
 * This can be a Servlet or JSP that will render a message stating that the
 * user has logged out.  If it is not sent, a {@code text/plain} message is
 * written to the HttpServletResponse stating that the user has logged out.</LI>
 * </UL>
 *
 * Instances of this class have a configurable commons-logging based logger
 * named
 * {@code com.logiclander.jaasmine.authentication.http.SPNegoFilter}.
 */
public class SimpleLogoutServlet extends HttpServlet {


    /** The logger for this instance. */
    private transient final Log logger =
            LogFactory.getLog(SimpleLogoutServlet.class);


    /**
     * The application name for the configuration to use in the JAAS file.  The
     * default value is
     * {@value AuthenticationService#DEFAULT_JAAS_SPNEGO_CONFIG}.
     */
    private String appName;


    /**
     * The name of a configured servlet that will do any logout post processing.
     * The value is the value of a servlet-name in the {@code web.xml} file.
     */
    private String postLogoutProcessorName;


    /**
     * {@inheritDoc}
     *
     * Checks the init-params for params named appName and
     * postLogoutProcessorName.  If these values are not specified, then
     * the default values are used.
     */
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


    /**
     * Logs out the Subject associated with the user.
     *
     * After the logout is done, the request is dispatched to a Servlet or JSP
     * specified by the {@code postLogoutProcessorName} init-param.  If the
     * param was not specified, a {@code text/plain} message will be written
     * to the response.
     *
     * This method is not idempotent.  If a request is made successfully once,
     * the user will be logged out.  Subsequent requests without a login will
     * cause an HTTP 403 - Forbidden to be returned.
     *
     * @param req the HttpServletRequest
     * @param resp the HttpServletResponse
     * @throws ServletException if a ServletException is thrown after the
     * request is dispatched to the post logout processor.
     * @throws IOException if an I/O error occurs.
     */
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
            sendPlainTextResponse(resp);
        }

    }


    /**
     * Writes a plain text message to the HttpServletResponse.
     *
     * @param resp the HttpServletResponse.
     * @throws ServletException If a ServletException is thrown.
     * @throws IOException if an I/O error occurs.
     */
    private void sendPlainTextResponse(HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("text/plain");
        PrintWriter w = resp.getWriter();
        w.println("You have been logged out");

        w.flush();
    }


    /**
     * Returns a hashcode for this SimpleAuthenticationService.
     *
     * @return a hashcode for this SimpleAuthenticationService.
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 17 * hash + (this.appName != null ? this.appName.hashCode() : 0);
        return hash;
    }


    /**
     * The String representation of this SimpleLogoutServlet.
     *
     * @return the String representation of this SimpleLogoutServlet.
     */
    @Override
    public String toString() {
        return String.format("%s for %s", this.getClass().getSimpleName(),
                appName);
    }


}
