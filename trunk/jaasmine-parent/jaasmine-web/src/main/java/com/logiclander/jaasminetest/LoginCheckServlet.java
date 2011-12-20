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

package com.logiclander.jaasminetest;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.logiclander.jaasmine.authentication.AuthenticationService;

/**
 * Example of a Login Servlet.  This servlet is named JaasLoginServlet in the
 * web.xml per the defaults of the JaasLoginFilter, which will dispatch to here
 * if the request is not authenticated.  Servlets like these can be used for
 * post JAAS authentication processing, such as establishing application
 * specific session information.
 *
 * A GET to this servlet means that JaasLoginFilter did not find the user's
 * Subject so the request will be forwarded to /WEB-INF/jsp/login.jsp to gather
 * the user's login credentials.
 *
 * A POST to this servlet means that JaasLoginFilter has accepted the login
 * credentials from the user and a Subject was obtained from the configured
 * store.
 *
 * @author <a href="mailto:andy@logiclander.com">Andy Gherna</a>
 */
public class LoginCheckServlet extends HttpServlet {


    private static final String DEFAULT_REDIRECT_AFTER_LOGIN = "/Home";

    private static final String LOGIN_JSP = "/WEB-INF/jsp/login.jsp";

    /**
     * Handles HTTP POST.
     *
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request,
        HttpServletResponse response) throws ServletException, IOException {

        HttpSession sess = request.getSession();

        String originalRequestUri =
    		(String) sess.getAttribute(AuthenticationService.REQUEST_URI_KEY);

        if (originalRequestUri != null) {

        	response.sendRedirect(originalRequestUri);

        } else {

            StringBuilder sb =
                    new StringBuilder(request.getContextPath());

	        response.sendRedirect(
	            sb.append(DEFAULT_REDIRECT_AFTER_LOGIN).toString()
	        );
        }
        return;
    }


    /**
     * Handles HTTP GET.
     *
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request,
        HttpServletResponse response) throws ServletException, IOException {

        RequestDispatcher rd =
            getServletContext().getRequestDispatcher(LOGIN_JSP);

        rd.include(request, response);
        return;
    }


    /**
     * @return the name of this class (LoginCheckServlet)
     */
    @Override
    public String toString() {
        return getClass().getSimpleName();
    }

}
