package com.logiclander.jaasmine.authentication.http;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

abstract class BaseHttpAuthorizor extends ChallengeHttpAuthorizor {

	private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

	private static final String AUTHORIZATION = "Authorization";

	private static final String DEFAULT_REALM_NAME = "Jaasmine";

	private final HttpServletRequest httpRequest;

    final Log httpAuthorizorLogger =
		LogFactory.getLog("httpAuthorizorLogger");

    BaseHttpAuthorizor(HttpServletRequest httpRequest) {
    	this(httpRequest, DEFAULT_REALM_NAME);
    }

	BaseHttpAuthorizor(HttpServletRequest httpRequest, String realmName) {
		super(realmName);
		this.httpRequest = checkNotNull(httpRequest);
	}

	@Override
	public void prepareUnauthorizedHttpResponse(HttpServletResponse httpResponse) {

		for (Challenge challenge : getChallenges()) {
			httpResponse.addHeader(
				WWW_AUTHENTICATE,
				challenge.getChallengeValue()
			);
		}

		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Override
	public AuthorizationType authorizationType() {
		AuthorizationType authzType = AuthorizationType.NULL;

		String requestType =
			getHeaderValueToken(httpRequest.getHeader(AUTHORIZATION), " ", 0);

		try {
			authzType = AuthorizationType.valueOf(requestType.toUpperCase());
		} catch (Exception e) {

			if (httpAuthorizorLogger.isInfoEnabled()) {
				httpAuthorizorLogger.info(
					String.format("Unsupported authorization type: %s", requestType)
				);
			}
			authzType = AuthorizationType.NULL;
		}

		return authzType;
	}


	@Override
	public String authorizationToken() {
		String authzToken = "";

		try {
			authzToken =
				getHeaderValueToken(httpRequest.getHeader(AUTHORIZATION), " ", 1);
		} catch (Exception e) {

			if (httpAuthorizorLogger.isInfoEnabled()) {
				httpAuthorizorLogger.info("No authorization token on Authorization header", e);
			}
			authzToken = "";
		}

		return authzToken;
	}


	String getHeaderValueToken(String headerValue, String delimiter, int tokenToGet) {

		String checkedHeaderValue = checkNotNull(headerValue);

		List<String> header = Arrays.asList(checkedHeaderValue.split(delimiter, 2));
		return header.get(tokenToGet);
	}


	@Override
	public boolean hasAuthorization() {
		return (httpRequest.getHeader(AUTHORIZATION) != null);
	}

	HttpServletRequest getHttpRequest() {
		return httpRequest;
	}

}
