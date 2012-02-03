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
import org.ietf.jgss.GSSException;

import com.logiclander.jaasmine.SPNegoServer;
import com.logiclander.jaasmine.authentication.AuthenticationService;

/**
 * Checks incoming ServletRequests and ServletResponses for authentication.
 *
 * This filter accepts the following init-params:
 * <UL>
 *  <LI>appName - the name of the application in the JAAS configuration.  This
 * parameter is optional.</LI>
 * </UL>
 *
 * Requests that invoke this Filter must have a {@code Authorization} header
 * and a {@code Negotiate} scheme with a valid SPNego token.  If any of these
 * requirements fail, then this Filter returns an HTTP 401 - Unauthorized with
 * a {@code WWW-Authenticate} header.
 *
 * Instances of this class have a configurable commons-logging based logger
 * named
 * {@code com.logiclander.jaasmine.authentication.http.SPNegoFilter}.
 */

//TODO - do we need to think about being able to generate Subjects in SSO situations?
public class SPNegoFilter implements Filter {

    /** The logger for this instance. */
    private transient final Log logger = LogFactory.getLog(SPNegoFilter.class);


    /**
     * The application name for the configuration to use in the JAAS file.
     */
    private String appName;


    public String filterName;


    /**
     * {@inheritDoc}
     *
     * Checks the given FilterConfig for the init-param named appName.  If this
     * value is not in the FilterConfig, then the default value is used.
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        appName = filterConfig.getInitParameter("appName");
        if (appName == null || appName.isEmpty()) {
            appName = AuthenticationService.DEFAULT_JAASMINE_LOGIN_CONFIG;
        }

        filterName = filterConfig.getFilterName();

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s initialized", toString()));
        }
    }


    /**
     * This implementation will filter requests for credentials and determine if
     * processing of the FilterChain can proceed.  Filtering occurs as follows:
     * <OL>
     *  <LI>If the request is not an HttpServletRequest and the response is not
     * an HttpServletResponse, continue processing the filter chain (this almost
     * never happens)</LI>
     *  <LI>The HttpServletRequest is checked for a {@code WWW-Authenticate}
     * request header.  If found, it is checked for the scheme used, which must
     * be set to {@code Negotiate}.</LI>
     *  <LI>If found, the SPNego token is decoded and validated.  If it is
     * valid, processing is allowed to continue.  If not, processing will stop
     * and an HTTP 401 is returned with a {@code WWW-Authenticate} request
     * header set to {@code Negotiate}.</LI>
     *  <LI>If the request header is not found, an HTTP 401 is returned with a
     * {@code WWW-Authenticate} request header set to {@code Negotiate}.</LI>
     * </OL>
     *
     * @param request the ServletRequest
     * @param response the ServletResponse
     * @param chain the FilterChain
     * @throws IOException if an I/O error occurs in the FilterChain
     * @throws ServletException if a processing error occurs in the FilterChain
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s: entering doFilter", filterName));
        }

        if (!(request instanceof HttpServletRequest) &&
                !(response instanceof HttpServletResponse)) {

            chain.doFilter(request, response);

        } else {

            HttpServletRequest httpReq = (HttpServletRequest) request;
            HttpServletResponse httpResp = (HttpServletResponse) response;

            if (logger.isDebugEnabled()) {
                logger.debug(
                    String.format("Filtering request: %s%s",
                        httpReq.getContextPath(), httpReq.getServletPath()));
            }

            String sPNegoToken = getSPNegoToken(httpReq);
            boolean canExecute = false;
            SPNegoServer server = null;

            try {

                server = new SPNegoServer(sPNegoToken);
                canExecute = server.isValidToken();

                // Wrap the HttpServletRequest with the requester's GSSName
                // so that additional processing can take place w/out having
                // to re-examine the SPNego token.
                httpReq = new JaasmineHttpServletRequest(
            		httpReq,
            		server.getRequesterName()
            	);

            } catch (GSSException ex) {

                if (logger.isDebugEnabled()) {

                    logger.debug("Problem with SPNego token", ex);

                } else {

                    logger.info(String.format("Problem with SPNego token: %s",
                         ex.getMessage()));

                }

                canExecute = false;

            } catch (Exception ex) {

            	if (logger.isFatalEnabled()){
            		logger.fatal(ex.getMessage(), ex);
            	}

            	canExecute = false;

            }

            if (canExecute) {

                chain.doFilter(httpReq, httpResp);

            } else {

                if (!httpResp.isCommitted()) {
                    httpResp.setHeader("WWW-Authenticate", "Negotiate");
                    httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }

            }
        }
    }


    /**
     * Writes a log message using the configured logger at DEBUG level stating
     * that the Filter is destroyed.
     */
    @Override
    public void destroy() {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s destroyed", toString()));
        }

    }


    /**
     * @return the String representation of this JaasLoginFilter.
     */
    @Override
    public String toString() {
        return String.format("%s for %s",
                filterName, appName);
    }


    private String getSPNegoToken(HttpServletRequest req) {

        String headerValue = req.getHeader("Authorization");
        if (headerValue == null || headerValue.isEmpty()) {
            return "";
        }

        // Split "Negotiate [SPNego_TOKEN]" by the space and return the token.

        String token = "";

        try {

        	token = headerValue.split(" ", 2)[1];

        } catch (RuntimeException t) {

        	logger.fatal(t.getMessage(), t);
        	throw t;

        }

        if (logger.isDebugEnabled()) {
        	logger.debug(String.format("%nSPNego token%n%s%n", token));
        }

        return token;
    }
}
