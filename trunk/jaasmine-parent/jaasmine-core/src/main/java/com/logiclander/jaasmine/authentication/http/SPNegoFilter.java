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
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author agherna
 */

//TODO - do we need to think about being able to generate Subjects in SSO situations?
public class SPNegoFilter implements Filter {

    private final Log logger = LogFactory.getLog(SPNegoFilter.class);

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

            HttpServletRequest hreq = (HttpServletRequest) request;
            HttpServletResponse hresp = (HttpServletResponse) response;

            boolean canExecute = hasValidSPNegoToken(hreq);

            if (canExecute) {

                // Wrap hreq and hresp so LoginFilter won't bother with it?
                //
                chain.doFilter(hreq, hresp);

            } else {

                if (!hresp.isCommitted()) {
                    hresp.addHeader("WWW-Authenticate", "Negotiate");
                    hresp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }

            }
        }
    }


    private boolean hasValidSPNegoToken(HttpServletRequest req) {

        // TODO: implement
        return false;
    }


    @Override
    public void destroy() {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s destroyed", toString()));
        }

    }


    public String toString() {
        return String.format("%s for %s", this.getClass().getSimpleName(),
                appName);
    }
}
