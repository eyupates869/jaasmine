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
 * named {@code com.logiclander.jaasmine.authentication.DefaultLoginService}.
 *
 * @author agherna
 */
public class SimpleAuthenticationService implements AuthenticationService {

    private final String applicationName;

    private final Log logger =
            LogFactory.getLog(SimpleAuthenticationService.class);


    public SimpleAuthenticationService(String applicationName) {
        this.applicationName = applicationName;
    }


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


    @Override
    public String toString() {
        return String.format("SimpleAuthenticationService for %s",
                applicationName);
    }


    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SimpleAuthenticationService other = (SimpleAuthenticationService) obj;
        if ((this.applicationName == null) ? (other.applicationName != null) : !this.applicationName.equals(other.applicationName)) {
            return false;
        }
        return true;
    }


    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + (this.applicationName != null ? this.applicationName.hashCode() : 0);
        return hash;
    }

}
