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

/**
 * Manages authentication lifecycle and provides standard names for keys used
 * by jaasmine services.
 */
public interface AuthenticationService {

    /**
     * A key that can be associated with the Subject returned by
     * {@link #login(java.lang.String, char[]) login}.
     */
    public static final String SUBJECT_KEY =
            "__com.logiclander.jaasmine.authentication.SUBJECT";

    public static final String REQUEST_URI_KEY =
    		"__com.logiclander.jaasmine.REQUEST_URI";
    
    public static final String REQUST_QUERY_KEY =
    		"__com.logiclander.jaasmine.REQUEST_QUERY";

    /**
     * The default application name for a configuration used by JAAS during the
     * authentication process.
     */
    public static final String DEFAULT_JAASMINE_LOGIN_CONFIG =
            "jaasmine.login";


    /**
     * Returns the Subject for the given credentials or null if the login fails
     * fails.
     *
     * @param userId the user's ID
     * @param password the password
     * @return the Subject associated with the supplied credentials
     */
    public Subject login(String userId, char[] password);


    /**
     * Logout the given Subject
     *
     * @param s the Subject to logout
     */
    public void logout(Subject s);

}
