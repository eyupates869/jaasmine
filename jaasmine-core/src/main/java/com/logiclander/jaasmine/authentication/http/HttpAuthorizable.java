package com.logiclander.jaasmine.authentication.http;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Abstraction for holding authorization functionality.
 * 
 * @author andy
 *
 */
interface HttpAuthorizable {
	
	/**
	 * @return an HttpServletRequest wrapped with information about the
	 * requester.
	 */
	HttpServletRequest getAuthorizedHttpRequest();

	
	/**
	 * Sets HTTP headers for an Unauthorized response.
	 * @param httpResponse
	 */
	void prepareUnauthorizedHttpResponse(HttpServletResponse httpResponse);
	
	/**
	 * 
	 * @return true if the HttpServletRequest contains an Authorization header.
	 */
	boolean hasAuthorization();
	
	/**
	 * 
	 * @return true if the HttpServletRequest is authorized.
	 */
	boolean isAuthorized();
	
	/**
	 * 
	 * @return the AuthorizationType for the HttpServletRequest.
	 */
	AuthorizationType authorizationType();
	
	
	/**
	 * 
	 * @return the Authorization token on the HttpServletRequest.
	 */
	String authorizationToken();
	
	
	/**
	 * 
	 * @return a List of Challenge objects to set on an unauthorized
	 * HttpServletResponse.
	 */
	List<Challenge> getChallenges();
}
