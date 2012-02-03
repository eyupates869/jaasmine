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

import com.logiclander.jaasmine.authentication.AuthenticationService;

public class GeneralAuthorizationFilter implements Filter {

	private final Log logger = LogFactory.getLog(getClass());
	
	private String appName;
	
	private String realmName;
	
	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain chain) throws IOException, ServletException {

        if (!(servletRequest instanceof HttpServletRequest) &&
            !(servletResponse instanceof HttpServletResponse)) {

        	if (logger.isDebugEnabled()) {
        		logger.debug("This is not an HTTP request");
        	}
        	
            chain.doFilter(servletRequest, servletResponse);

        } else {
        	
        	HttpServletRequest httpRequest = 
        			(HttpServletRequest) servletRequest;
        	HttpServletResponse httpResponse = 
        			(HttpServletResponse) servletResponse;
        	
        	try {
        		
				HttpAuthorizable httpAuthorizor = getHttpAuthorizor(httpRequest);
				
				if (httpAuthorizor.isAuthorized()) {
					
					httpRequest = httpAuthorizor.getAuthorizedHttpRequest();
					chain.doFilter(httpRequest, httpResponse);
					
				} else {
					
					if (!httpResponse.isCommitted()) {
						httpAuthorizor.prepareUnauthorizedHttpResponse(httpResponse);
					}
					
					return;
				}
				
			} catch (HttpAuthorizorException e) {
				
				if (logger.isWarnEnabled()) {
					logger.warn("Problem checking HTTP request", e);
				}
				
				httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "There was a problem checking this request. Please try again later.");
				return;
			}
        	
        }
	}

	private HttpAuthorizable getHttpAuthorizor(HttpServletRequest httpRequest) throws HttpAuthorizorException {
		
		HttpAuthorizable httpAuthorizor = new NonAuthorizingHttpAuthorizor(httpRequest);

		if (httpAuthorizor.hasAuthorization()) {
			if (AuthorizationType.BASIC.equals(httpAuthorizor.authorizationType())) {
				httpAuthorizor = new BasicHttpAuthorizor(httpRequest, realmName, appName);
			} else if (AuthorizationType.NEGOTIATE.equals(httpAuthorizor.authorizationType())) {
				httpAuthorizor = new NegotiateHttpAuthorizor(httpRequest, realmName);
			}
		}
		
		return httpAuthorizor;
	}
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		appName = filterConfig.getInitParameter("appName");
		
		if (appName == null) {
			appName = AuthenticationService.DEFAULT_JAASMINE_LOGIN_CONFIG;
		}
		
		realmName = filterConfig.getInitParameter("realmName");
		if (realmName == null) {
			realmName = "Jaasmine";
		}
	}
	
	
	
}
