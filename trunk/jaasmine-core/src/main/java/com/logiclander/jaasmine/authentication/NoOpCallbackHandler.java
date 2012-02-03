package com.logiclander.jaasmine.authentication;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A CallbackHandler that does nothing. This is a placeholder implementation
 * used whenever logins need to be automated. For example, this would be used
 * in a Kerberos authentication by a service account that had a keytab file
 * configured for it.
 *
 * @author andy
 *
 */
class NoOpCallbackHandler implements CallbackHandler {

	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * {@inheritDoc}
	 *
	 * This implementation will log a warning if it is called since it would
	 * mean that there's a problem with the JAAS configuration.
	 */
	@Override
	public void handle(Callback[] cbj) throws IOException,
			UnsupportedCallbackException {

		if (logger.isWarnEnabled()) {
			logger.warn("Invoking this handler means JAAS is misconfigured");
		}
	}

}
