package com.logiclander.jaasmine.authentication.http;

import javax.servlet.http.HttpServletRequest;

public class NonAuthorizingHttpAuthorizor extends BaseHttpAuthorizor {

	NonAuthorizingHttpAuthorizor(HttpServletRequest httpRequest) {
		super(httpRequest);
	}

	@Override
	public HttpServletRequest getAuthorizedHttpRequest() {
		return getHttpRequest();
	}

	@Override
	public boolean isAuthorized() {
		return false;
	}

}
