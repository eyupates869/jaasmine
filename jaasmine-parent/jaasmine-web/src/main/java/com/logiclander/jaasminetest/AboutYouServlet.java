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

import com.logiclander.jaasmine.authentication.AuthenticationService;
import java.io.IOException;
import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Example of an HttpServlet protected by JaasLoginFilter that implements HTTP
 * GET.
 *
 * @author <a href="mailto:andy@logiclander.com">Andy Gherna</a>
 */
public class AboutYouServlet extends HttpServlet {


    /**
     * Handles HTTP GET.  This method will try to find the Subject set by
     * the JaasLoginFilter.  If not found, an HTTP 401 - Unauthorized is
     * returned.  If found, the Subject is dispatched to the servlet named
     * AboutYouJsp.
     *
     * @param req the HttpServletRequest
     * @param resp the HttpServletResponse
     * @throws ServletException if a ServletException is thrown
     * @throws IOException if an IOException is thrown
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws ServletException, IOException {

        HttpSession sess = req.getSession(false);
        if (sess == null) {
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Subject s =
                (Subject) sess.getAttribute(AuthenticationService.SUBJECT_KEY);

        if (s == null) {
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        req.setAttribute("subject", s.toString());

        RequestDispatcher rd =
                getServletContext().getNamedDispatcher("AboutYouJsp");
        rd.forward(req, resp);

        return;
    }

    
    /**
     * @return the name of this class (AboutYouServlet)
     */
    @Override
    public String toString() {
        return getClass().getSimpleName();
    }

}
