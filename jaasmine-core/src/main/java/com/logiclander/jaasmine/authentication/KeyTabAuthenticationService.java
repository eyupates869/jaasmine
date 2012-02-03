package com.logiclander.jaasmine.authentication;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An AuthenticationService that relies on a Kerberos keytab
 * file for credentials. This implementation should be used with the JAAS
 * configuration described below:
 *
 * {@code <PRE>
 * jaasmine.login {
 *   com.sun.security.auth.module.Krb5LoginModule
 *   required
 *   useKeyTab=true
 *   doNotPrompt=true
 *   storeKey=true
 *   keyTab="/path/to/keytab"
 *   principal="SVC/server.host.name@MYDOMAIN.COM"
 *   ;
 *  };
 * </PRE>}
 *
 * Instances of this class have a configurable commons-logging based logger
 * named
 * {@code com.logiclander.jaasmine.authentication.KeyTabAuthenticationService}.
 */
public class KeyTabAuthenticationService extends BaseAuthenticationService {

	private final Log logger = LogFactory.getLog(getClass());

	private final String applicationName;

	public KeyTabAuthenticationService() {
		this(DEFAULT_JAASMINE_LOGIN_CONFIG);
	}

	public KeyTabAuthenticationService(String applicationName) {
		this.applicationName = applicationName;
	}

	/**
	 * {@inheritDoc}
	 *
	 * The parameters for this method are ignored since the keytab is
	 * configured using the configuration described above.
	 */
	@Override
	public Subject login(String userId, char[] password) {

        Subject s = null;

        try {

        	// The CallbackHandler doesn't need to do any work, so the
        	// NoOpCallbackHandler implementation is used.
            CallbackHandler cbh = new NoOpCallbackHandler();
            s = doLogin(applicationName, cbh);

        } catch (LoginException ex) {

            if (logger.isInfoEnabled()) {
                String msg =
                        String.format("JAAS configuration problem: %s",
                            ex.getMessage());
                logger.info(msg, ex);
            }
            s = null;
        }

        return s;
	}

	@Override
	public void logout(Subject s) {

        try {

        	doLogout(applicationName, s);

        } catch (LoginException ex) {

            if (logger.isInfoEnabled()) {
                String msg =
                        String.format("Logout failed: %s", ex.getMessage());
                logger.info(msg);
            }

        }
	}

}
