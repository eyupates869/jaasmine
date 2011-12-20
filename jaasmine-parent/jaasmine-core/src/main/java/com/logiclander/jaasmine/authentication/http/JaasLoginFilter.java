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

import javax.security.auth.Subject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.logiclander.jaasmine.authentication.AuthenticationService;
import com.logiclander.jaasmine.authentication.SimpleAuthenticationService;

/**
 * Checks incoming ServletRequests and ServletResponses for authentication.
 *
 * This filter accepts the following init-params:
 * <UL>
 *  <LI>appName - the name of the application in the JAAS configuration.  This
 * parameter is optional.  The default value is
 * {@value AuthenticationService#DEFAULT_JAASMINE_LOGIN_CONFIG}</LI>
 *  <LI>loginPath - if set, dispatch to this path in the web application.  This
 * can be a JSP, Servlet or HTML page.</LI>
 *  <LI>loginRedirect - if set, redirect to this URL for login processing and/or
 * credential gathering.  The value can be a relative or absolute URL.  If the
 * redirect is relative (that is, inside the web application), a servlet or
 * JSP must be mapped to the URL listed here in the web.xml file.</LI>
 *  <LI>loginServletName - the name of the Servlet that will be used to
 * collect user credentials.  This parameter is optional.  The default value is
 * {@value #DEFAULT_NAMED_LOGIN_DISPATCHER}</LI>
 *  <LI>setRemoteUserOnLogin - when "true", calls to
 * {@link javax.servlet.http.HttpServletRequest#getRemoteUser() getRemoteUser}
 * will return the user name that was used by the user to log in.  The default
 * value is {@value #DEFAULT_SET_REMOTE_USER_ON_LOGIN}</LI>
 * </UL>
 *
 * Requests that invoke this Filter must have parameters named {@code username}
 * and {@code password} set, otherwise the request cannot be processed.  This
 * Filter processes logins using the {@link SimpleAuthenticationService}.
 *
 * Instances of this class have a configurable commons-logging based logger
 * named
 * {@code com.logiclander.jaasmine.authentication.http.JaasLoginFilter}.
 */
public class JaasLoginFilter implements Filter {


    /** The logger for this instance. */
    private transient final Log logger =
            LogFactory.getLog(JaasLoginFilter.class);


    /** The default value for the appName, which is {@value}.*/
    private static final String DEFAULT_NAMED_LOGIN_DISPATCHER =
            "JaasLoginServlet";


    /** The default value for setRemoteUserOnLogin, which is {@value}.*/
    private static final String DEFAULT_SET_REMOTE_USER_ON_LOGIN = "false";


    /** Empty String flag used to stop some processing of login handling. */
    private static final String EMPTY_STRING = "";


    /**
     * The application name for the configuration to use in the JAAS file.  The
     * default value is
     * {@value AuthenticationService#DEFAULT_JAASMINE_LOGIN_CONFIG}.
     */
    private String appName;


    private String filterName;


    /**
     * Dispatch to this path in the web context if set.  If this is set, the
     * loginRedirect and loginServletName are ignored.
     */
    private String loginPath;


    /**
     * Redirect to this URL if set.  This could be in or out of the web
     * application.  If this is set, the loginServletName is ignored.
     */
    private String loginRedirect;


    /**
     * The name of the Servlet to use for post login processing.  The default
     * value is {@value #DEFAULT_NAMED_LOGIN_DISPATCHER}.
     */
    private String loginServletName;


    /**
     * Flag indicating whether or not to set the REMOTE_USER on a successful
     * login.  The default value is {@value #DEFAULT_SET_REMOTE_UESR_ON_LOGIN}.
     */
    private boolean setRemoteUserOnLogin;


    private boolean isUsingBasicAuthentication;

    /**
     * {@inheritDoc}
     *
     * Checks the given FilterConfig for the init-params named appName and
     * loginServletName.  If these values are not in the FilterConfig, then
     * the default values are used.
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        appName = filterConfig.getInitParameter("appName");
        if (appName == null || appName.isEmpty()) {
            appName = AuthenticationService.DEFAULT_JAASMINE_LOGIN_CONFIG;
        }

        loginPath = filterConfig.getInitParameter("loginPath");
        if (loginPath == null || loginPath.isEmpty()) {
            loginPath = EMPTY_STRING;
        }

        loginRedirect = filterConfig.getInitParameter("loginRedirect");
        if (loginRedirect == null || loginRedirect.isEmpty()) {
            loginRedirect = EMPTY_STRING;
        }

        loginServletName = filterConfig.getInitParameter("loginServletName");
        if (loginServletName == null || loginServletName.isEmpty()) {
            loginServletName = DEFAULT_NAMED_LOGIN_DISPATCHER;
        }

        String setRemoteUserOnLoginParam =
                filterConfig.getInitParameter("setRemoteUserOnLogin");
        if (setRemoteUserOnLoginParam == null ||
                setRemoteUserOnLoginParam.isEmpty()) {
            setRemoteUserOnLoginParam = DEFAULT_SET_REMOTE_USER_ON_LOGIN;
        }

        setRemoteUserOnLogin = Boolean.parseBoolean(setRemoteUserOnLoginParam);

        filterName = filterConfig.getFilterName();

        isUsingBasicAuthentication = Boolean.valueOf(filterConfig.getInitParameter("setBasicAuth"));

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("%s initialized", toString()));
            logger.debug(String.format("loginPath = %s",
                    loginPath == EMPTY_STRING ? "Not set" : loginPath));
            logger.debug(String.format("loginRedirect = %s",
                    loginRedirect == EMPTY_STRING ? "Not set" : loginRedirect));
            logger.debug(String.format("loginServletName = %s",
                    loginServletName));
            logger.debug(String.format("setRemoteUserOnLogin = %s",
                    Boolean.toString(setRemoteUserOnLogin)));
        }
    }


    /**
     * This implementation will filter requests for credentials and determine if
     * processing of the FilterChain can proceed.  Filtering occurs as follows:
     * <OL>
     *  <LI>If the request is not an HttpServletRequest and the response is not
     * an HttpServletResponse, continue processing the filter chain (this almost
     * never happens)</LI>
     *  <LI>The HttpSession is checked for an attribute named
     * {@link AuthenticationService#SUBJECT_KEY
     * AuthenticationService.SUBJECT_KEY}</LI>
     *  <LI>If found, then processing the filter chain continues.</LI>
     *  <LI>If not found, then the request is checked for the {@code username}
     * and {@code password} parameters.  If these parameters are present, then
     * the SimpleAuthenticationService's login method is invoked with those
     * credentials.</LI>
     *  <LI>If a Subject is returned, it is saved to the HttpSession with the
     * key from above.</LI>
     * </OL>
     * When the login is successful, the ServletRequest is wrapped in a
     * {@link JaasmineHttpServletRequest}.  If it is unsuccessful, this filter
     * will send the request to a login processor as follows:
     * <OL>
     *  <LI>If {@code loginPath} is set, dispatch the request to that resource.
     * </LI>
     *  <LI>If (@code loginRedirect} is set, redirect the request to that URL.
     * </LI>
     *  <LI>Dispatch to {@code loginServletName} if neither of the above are
     * set./LI>
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

            logger.debug("This is not an HTTP request");
            chain.doFilter(request, response);

        } else {

            HttpServletRequest httpReq = (HttpServletRequest) request;
            HttpServletResponse httpResp = (HttpServletResponse) response;

            Exception exception = null;

            if (logger.isDebugEnabled()) {
                logger.debug(
                    String.format("Filtering request: %s%s",
                        httpReq.getContextPath(), httpReq.getServletPath()));
            }

            try {

            	if (! hasRequestUri(httpReq)) {
            		cacheRequestUri(httpReq);
            	}

                boolean canExecute = hasCredentials(httpReq);

                // Attempt to login the user and obtain a Subject.

                if (!canExecute) {
                    canExecute = login(httpReq);
                }

                if (canExecute) {

                    // The Subject was found which means the user has a valid
                    // credential (Subject).  Processing can continue.

                	// TODO: always wrap request, set to cached requestURI
                    HttpServletRequest sendOn = httpReq;

                    if (setRemoteUserOnLogin) {
                        sendOn = new JaasmineHttpServletRequest(httpReq,
                                    getSubject(httpReq));
                        logger.debug(String.format("Wrapping request in %s",
                                sendOn.toString()));

                    }

                    chain.doFilter(sendOn, httpResp);

                } else {

                    // No Subject found, need to dispatch to someplace to gather
                    // the user's credentials and attempt a login on the
                    // next request.

                    RequestDispatcher loginDispatcher = null;
                    if (!loginPath.equals(EMPTY_STRING)) {

                        loginDispatcher =
                            httpReq.getSession()
                                .getServletContext()
                                .getRequestDispatcher(loginPath);

                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Dispatching login "
                                    + "request to path %s", loginPath));
                        }

                    } else if (!loginRedirect.equals(EMPTY_STRING)) {

                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Redirectiong login "
                                    + "request to %s", loginRedirect));
                        }
                        httpResp.sendRedirect(loginRedirect);


                        // TODO: cache incoming requestURI

                        return;

                    } else if (isUsingBasicAuthentication) {

                        String s = "Basic realm=\"Jaasmine\"";
                        httpResp.setHeader("WWW-Authenticate", s);
                        httpResp.setStatus(401);

                        return;
                    } else {

                        loginDispatcher =
                            httpReq.getSession()
                                .getServletContext()
                                .getNamedDispatcher(loginServletName);

                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Dispatching login "
                                    + "request to named dispatcher %s",
                                    loginServletName));
                        }
                    }

                    if (loginDispatcher != null) {

                        loginDispatcher.forward(httpReq, httpResp);
                        return;

                    } else {

                        // Try to figure out what went wrong and send back
                        // a HELPFUL exception message.

                        String msg = "";

                        if (!loginPath.equals(EMPTY_STRING)) {

                            // First, is there a loginPath set, but nowhere to
                            // send it to?

                            msg =
                                String.format("loginPath set to %s, but no "
                                    + "resource is available to dispatch to",
                                    loginPath);
                        } else {

                            // Is JaasLoginServlet (or the servlet-name
                            // specified by loginServletName) not configured in
                            // the web.xml?

                            msg =
                                String.format("Servlet named %s specified by "
                                + "the loginServletName is not configured in "
                                + "the web.xml", loginServletName);
                        }

                        throw new ServletException(msg);

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
        return String.format("%s for %s", filterName,
                appName);
    }


    /**
     * @param req an HttpServletRequest
     * @return true if the session has been established AND the request URI is cached.
     */
    private boolean hasRequestUri(HttpServletRequest req) {

    	HttpSession sess = req.getSession(false);
    	if (sess == null) {
    		return false;
    	}

    	String requestURI =
    		(String) sess.getAttribute(AuthenticationService.REQUEST_URI_KEY);

    	return (requestURI != null);
    }


    private void cacheRequestUri(HttpServletRequest req) {

    	HttpSession sess = req.getSession();

    	sess.setAttribute(AuthenticationService.REQUEST_URI_KEY, req.getRequestURI());

    	if (req.getQueryString() != null) {
    		sess.setAttribute(AuthenticationService.REQUST_QUERY_KEY, req.getQueryString());
    	}
    }


    /**
     * @param req an HttpServletRequest
     * @return true if the credentials are present on the request.
     */
    private boolean hasCredentials(HttpServletRequest req) {

        return hasSubject(req);

    }


    /**
     * @param req an HttpServletRequest
     * @return true if the Subject is found on the request.
     */
    private boolean hasSubject(HttpServletRequest req) {

        HttpSession sess = req.getSession(false);
        if (sess == null) {
            return false;
        }

        Subject subj =
            (Subject) sess.getAttribute(AuthenticationService.SUBJECT_KEY);

        return (subj != null);
    }


    /**
     * @param request the HttpServletRequest.
     * @return true if the Subject is obtained from the SimpleLoginService.
     */
    private boolean login(HttpServletRequest request) {

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        boolean subjectObtained = false;

        if (username == null && password == null) {

        	String basic = request.getHeader("Authorization");

        	if (basic != null) {

        		String[] hTokens = basic.split(" ");

	        	String decoded = new String(Base64.decodeBase64(hTokens[1]));

	        	String[] aTokens = decoded.split(":");
	        	username = aTokens[0];

	        	// Allow for the possibility of a machine-based login w/out a
	        	// password
	        	if (aTokens.length > 1) {
	        		password = aTokens[1];
	        	} else {
	        		password = "";
	        	}
        	}
        }

        if (username == null || username.isEmpty()) {

            logger.debug("username is missing");
            return subjectObtained;

        }

//        if (password == null || password.isEmpty()) {
//
//            logger.debug("password is missing");
//            return subjectObtained;
//        }

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


    /**
     * @param request the HttpServletRequest
     * @return the Subject obtained from a successful login.
     */
    private Subject getSubject(HttpServletRequest request) {

        HttpSession s = request.getSession();
        return (Subject) s.getAttribute(AuthenticationService.SUBJECT_KEY);
    }
}
