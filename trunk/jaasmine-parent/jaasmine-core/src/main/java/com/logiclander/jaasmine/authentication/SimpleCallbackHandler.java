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

import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 *
 * @author agherna
 */
class SimpleCallbackHandler implements CallbackHandler {


    private final String userId;

    private final char[] password;

    SimpleCallbackHandler(String userId, char[] password) {
        this.userId = userId;
        this.password = password;
    }

    
    /**
     * Retrieve or display the information requested in the provided Callbacks.
     *
     * This implementation only checks for a
     * {@link javax.security.auth.callback.NameCallback NameCallback} and
     * {@link javax.security.auth.callback.PasswordCallback PasswordCallback}.
     * Other Callbacks cause an UnsupportedCallbackException to be thrown.
     *
     * @param callbacks an array of Callback objects provided by an underlying
     * security service which contains the information requested to be
     * retrieved or displayed.
     * @throws IOException if an input or output error occurs.
     * @throws UnsupportedCallbackException if a Callback is not either a
     * NameCallback or PasswordCallback.
     */
    @Override
    public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException {

        for (Callback cb : callbacks) {

            if (cb instanceof NameCallback) {
                NameCallback nc = (NameCallback) cb;
                nc.setName(userId);
                continue;
            }

            if (cb instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) cb;
                pc.setPassword(password);
                continue;
            }

            throw new UnsupportedCallbackException(cb, "Unsupported Callback");
        }
    }

}
