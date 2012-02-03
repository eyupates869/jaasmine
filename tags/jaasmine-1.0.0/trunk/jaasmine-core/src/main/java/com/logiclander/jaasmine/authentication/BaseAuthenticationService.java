package com.logiclander.jaasmine.authentication;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Base implementation of AuthenticationService.
 */
public abstract class BaseAuthenticationService implements AuthenticationService {

	/**
	 * Performs the login.
	 *
	 * @param applicationName the name of the JAAS configuration to use. This
	 * should match one of the configurations in the JAAS configuration file
	 * specified by the {@code java.security.auth.login.config} System
	 * property.
	 * @param cbh the CallbackHandler for performing the login.
	 * @return the user's Subject.
	 * @throws LoginException if a problem occurs during login.
	 */
	Subject doLogin(String applicationName, CallbackHandler cbh)
			throws LoginException {

        LoginContext lc = new LoginContext(applicationName, cbh);
        lc.login();

        return lc.getSubject();

	}

	/**
	 * Performs the logout.
	 *
	 * @param applicationName the name of the JAAS configuration to use. This
	 * should match one of the configurations in the JAAS configuration file
	 * specified by the {@code java.security.auth.login.config} System
	 * property.
	 * @param subject the Subject to logout.
	 * @throws LoginException if a problem occurs during logout.
	 */
	void doLogout(String applicationName, Subject subject)
			throws LoginException {

        LoginContext lc = new LoginContext(applicationName, subject);
        lc.logout();
	}

}
