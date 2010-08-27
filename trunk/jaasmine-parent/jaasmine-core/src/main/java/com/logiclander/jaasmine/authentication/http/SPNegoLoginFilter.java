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
import javax.security.auth.Subject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author agherna
 */
public class SPNegoLoginFilter implements Filter {


    private Log logger = LogFactory.getLog(SPNegoLoginFilter.class);

    private String appName;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        appName = filterConfig.getInitParameter("appName");
        if (appName == null || appName.isEmpty()) {
            appName = AuthenticationService.DEFAULT_JAAS_SPNEGO_CONFIG;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s initialized", toString()));
        }

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
            FilterChain chain) throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest) &&
            !(response instanceof HttpServletResponse)) {

            chain.doFilter(request, response);

        } else {

            HttpServletRequest httpReq = (HttpServletRequest) request;
            HttpServletResponse httpResp = (HttpServletResponse) response;

            Exception exception = null;

            try {

                boolean canExecute = hasCredentials(httpReq);

                if (!canExecute) {
                    canExecute = login(httpReq);
                }

                if (canExecute) {

                    chain.doFilter(httpReq, httpResp);

                } else {

                    if (!httpResp.isCommitted()) {
                        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                        return;
                    }
                    
                }

            } catch (IOException ex) {

                exception = ex;
                throw(ex);

            } catch (ServletException ex) {

                exception = ex;
                throw(ex);

            } finally {

                if (exception != null) {

                    if (logger.isErrorEnabled()) {
                        String msg =
                            String.format("Caught exception in filter chain: %s",
                                exception.getMessage());
                        logger.error(msg, exception);
                    }
                }

            }
        }
    }


    private boolean hasCredentials(HttpServletRequest req) {

        boolean subjectSet = false;
        boolean spnegoTokenPresent = false;

        subjectSet = hasSubject(req);

        if (!subjectSet) {
            spnegoTokenPresent = hasValidSPNegoToken(req);
        }

        return (subjectSet || spnegoTokenPresent);
    }


    private boolean hasSubject(HttpServletRequest req) {

        HttpSession sess = req.getSession(false);
        if (sess == null) {
            return false;
        }

        Subject subj =
            (Subject) sess.getAttribute(AuthenticationService.SUBJECT_KEY);

        return (subj != null);
    }


    private boolean hasValidSPNegoToken(HttpServletRequest req) {

        // TODO: implement
        return false;
    }


    private boolean login(HttpServletRequest request) {

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        boolean subjectObtained = false;

        if (username == null || username.isEmpty()) {

            if (logger.isDebugEnabled()) {
                logger.debug("username is missing");
            }
            return subjectObtained;

        }

        if (password == null || password.isEmpty()) {

            if (logger.isDebugEnabled()) {
                logger.debug("password is missing");
            }
            return subjectObtained;
        }

        AuthenticationService as = new SimpleAuthenticationService(appName);
        Subject s = as.login(username, password.toCharArray());
        subjectObtained = (s != null);

        if (subjectObtained) {

            // Assuming that if we got here, we need to create the session
            HttpSession sess = request.getSession();
            sess.setAttribute(AuthenticationService.SUBJECT_KEY, s);
        }
        
        return subjectObtained;
    }


    @Override
    public void destroy() {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s destroyed", toString()));
        }

    }


    @Override
    public String toString() {
        return String.format("%s for %s", this.getClass().getSimpleName(),
                appName);
    }
}
