package com.logiclander.jaasmine.authentication.http;

import javax.servlet.http.HttpServletRequest;

import org.ietf.jgss.GSSException;

import com.logiclander.jaasmine.SPNegoServer;

class NegotiateHttpAuthorizor extends BaseHttpAuthorizor {

	private final SPNegoServer spnegoServer;
	
	NegotiateHttpAuthorizor(HttpServletRequest httpRequest) throws HttpAuthorizorException {
		super(httpRequest);
		spnegoServer = createSPNegoServer();
	}

	public NegotiateHttpAuthorizor(HttpServletRequest httpRequest,
			String realmName) throws HttpAuthorizorException {
		super(httpRequest, realmName);
		spnegoServer = createSPNegoServer();
	}

	private SPNegoServer createSPNegoServer() throws HttpAuthorizorException {
		
		try {
			
			return new SPNegoServer(authorizationToken());
			
		} catch (GSSException e) {
			
			if (httpAuthorizorLogger.isWarnEnabled()) {
				httpAuthorizorLogger.warn("Problem initialzing SPNegoServer", e);
			}
			
			throw new HttpAuthorizorException(e);
		}
	}
	
	
	@Override
	public HttpServletRequest getAuthorizedHttpRequest() {
		HttpServletRequest authzdHttpRequest = null;
		
		try {
			
			authzdHttpRequest =
				new JaasmineHttpServletRequest(
					getHttpRequest(), 
					spnegoServer.getRequesterName()
				);
			
		} catch (GSSException e) {
			
			if (httpAuthorizorLogger.isWarnEnabled()) {
				httpAuthorizorLogger.warn("Problem getting requester name", e);
			}
			
			if (httpAuthorizorLogger.isDebugEnabled()) {
				httpAuthorizorLogger.debug("Returning original HttpServletRequest");
			}
			
			authzdHttpRequest = getHttpRequest();
		}
		
		return authzdHttpRequest;
	}

	@Override
	public boolean isAuthorized() {
		return spnegoServer.isValidToken();
	}

}
