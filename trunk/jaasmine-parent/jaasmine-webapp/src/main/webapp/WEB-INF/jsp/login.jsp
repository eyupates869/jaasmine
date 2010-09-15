<%--
 Copyright 2010 LogicLander

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
--%>

<%--
 This JSP contains the login form.  The form has 3 parameters defined:

 username:
    The user's username (required by JaasLoginFilter).
 password:
    The user's password (required by JaasLoginFilter).
 redirect_after_login:
    PATH_INFO (target) of a resource in this application to send the user to
    after they are logged in (required by JaasLoginServlet).

--%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=MacRoman">
        <title>Login</title>
    </head>
    <body>
        <h1>Log in to this application</h1>
        <form action="Login" method="POST">
            <label for="username">UserName:</label>
            <input type="text" name="username" id="username"/>
            <br/>
            <label for="password">Password:</label>
            <input type="password" name="password" id="password"/>
            <br/>
            <input type="hidden" name="redirect_after_login" value="<c:out value="${redirectAfterLogin}"/>"/>
            <input type="submit" value="Login"/>
        </form>
    </body>
</html>
