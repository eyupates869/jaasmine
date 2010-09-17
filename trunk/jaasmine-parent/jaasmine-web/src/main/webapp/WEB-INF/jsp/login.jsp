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

--%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=MacRoman">
        <title>Login</title>
        <link rel="stylesheet" href="looks.css" type="text/css" media="screen"/>
    </head>
    <body>
        <h1>Log in to this application</h1>

        <form action="Login" method="POST">
            <ol>
                <li>
                    <label for="username">UserName:</label>
                    <input type="text" name="username" id="username"/>
                </li>
                <li>
                    <label for="password">Password:</label>
                    <input type="password" name="password" id="password"/>
                </li>
                <li>
                    <input type="submit" value="Login"/>
                </li>
            </ol>
        </form>
    </body>
</html>
