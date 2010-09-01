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

package com.logiclander.jaasmine.authentication;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A default AuthenticationService implementation that authenticates users based
 * on userId and password, using a default
 * {@link javax.security.auth.callback.CallbackHandler CallbackHandler}.
 *
 * Instances of this class have a configurable commons-logging based logger
 * named 
 * {@code com.logiclander.jaasmine.authentication.SimpleAuthenticationService}.
 */
public class SimpleAuthenticationService implements AuthenticationService {


    /** The JAAS configuration to use for this instance. */
    private final String applicationName;


    /** The logger for this instance. */
    private transient final Log logger =
            LogFactory.getLog(SimpleAuthenticationService.class);


    /**
     * Constructs a new SimpleAuthenticationService that will use the
     * configuration under the given application name in the JAAS configuration.
     *
     * @param applicationName the application name
     */
    public SimpleAuthenticationService(String applicationName) {
        this.applicationName = applicationName;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Subject login(String userId, char[] password) {

        Subject s = null;

        try {

            CallbackHandler cbh = new SimpleCallbackHandler(userId, password);
            LoginContext lc = new LoginContext(applicationName, cbh);
            lc.login();

            s = lc.getSubject();
        } catch (LoginException ex) {

            if (logger.isInfoEnabled()) {
                String msg =
                        String.format("Could not log in %s: %s",
                            userId,
                            ex.getMessage());
                logger.info(msg);
            }
            s = null;
        }

        return s;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void logout(Subject s) {

        try {

            LoginContext lc = new LoginContext(applicationName, s);
            lc.logout();

        } catch (LoginException ex) {

            if (logger.isInfoEnabled()) {
                String msg =
                        String.format("Logout failed: %s", ex.getMessage());
                logger.info(msg);
            }
            
        }
    }


    /**
     * The String representation of this SimpleAuthenticationService.
     *
     * @return the String representation of this SimpleAuthenticationService.
     */
    @Override
    public String toString() {
        return String.format("%s for %s", getClass().getSimpleName(),
                applicationName);
    }


    /**
     * Compares the specified Object with this SimpleAuthenticationService for
     * equality.  Returns true if the object is also a
     * SimpleAuthenticationService and the two SimpleAuthenticationService
     * instances are equivalent.  More formally, two SimpleAuthenticationService
     * instances are equal if their application names are equal.
     *
     * @param obj Object to be compared with this SimpleAuthenticationService
     * for equality.
     * @return true if the specified Object is equal to this
     * SimpleAuthenticationService.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SimpleAuthenticationService other =
                (SimpleAuthenticationService) obj;
        if ((this.applicationName == null) ? (other.applicationName != null) :
            !this.applicationName.equals(other.applicationName)) {
            return false;
        }
        return true;
    }


    /**
     * Returns a hashcode for this SimpleAuthenticationService.
     *
     * @return a hashcode for this SimpleAuthenticationService.
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + (this.applicationName != null ?
            this.applicationName.hashCode() : 0);
        return hash;
    }

}
