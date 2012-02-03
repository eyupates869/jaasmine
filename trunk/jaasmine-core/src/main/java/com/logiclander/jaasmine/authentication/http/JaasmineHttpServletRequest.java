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

package com.logiclander.jaasmine.authentication.http;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.ietf.jgss.GSSName;

/**
 * Custom HttpServletRequestWrapper for accessing Jaasmine constructs via the
 * servlet API.
 *
 */
class JaasmineHttpServletRequest extends HttpServletRequestWrapper {

    private final HttpServletRequest wrapped;

    private final Principal userPrincipal;

    /**
     * Constructs a new JaasmineHttpServletRequest.
     *
     * @param toWrap the HttpServletRequest to wrap
     * @param user the name of the user.
     */
    JaasmineHttpServletRequest(HttpServletRequest toWrap, Subject subject) {
        super(toWrap);
        this.wrapped = toWrap;

        Set<Principal> principals = subject.getPrincipals();
        userPrincipal = principals.iterator().next();

    }


    JaasmineHttpServletRequest(HttpServletRequest toWrap, GSSName name) {
    	super(toWrap);
    	this.wrapped = toWrap;

    	userPrincipal = new GSSNamePrincipal(name);
    }


    /**
     * {@inheritDoc }
     *
     * The remote user is the user's Principal.  If it's a Kerberos principal,
     * only the portion before the {@code @} symbol is returned.
     */
    @Override
    public String getRemoteUser() {
        return userPrincipal.getName().split("@")[0];
    }

    /**
     * @return the user's Principal.
     */
    @Override
    public Principal getUserPrincipal() {
        return userPrincipal;
    }


    /**
     * @return a String representation of this JaasmineHttpServletRequest.
     */
    @Override
    public String toString() {
        return String.format("%s:userPrincipal = %s, REMOTE_USER = %s",
                this.getClass().getSimpleName(),
                userPrincipal.toString(),
                this.getRemoteUser());
    }


    private static final class GSSNamePrincipal implements Principal {

    	private final GSSName name;

    	GSSNamePrincipal(GSSName name) {
    		this.name = name;
    	}

		@Override
		public String getName() {
			return name.toString();
		}

		@Override
		public boolean equals(Object other) {
			return name.equals(other);
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public String toString() {
			return name.toString();
		}

    }
}
