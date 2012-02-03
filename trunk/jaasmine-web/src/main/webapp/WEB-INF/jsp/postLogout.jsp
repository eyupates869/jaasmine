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
 This is a custom JSP displayed after the Subject has been logged out.
--%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>You have been logged out</title>
        <link rel="stylesheet" href="looks.css" type="text/css" media="screen"/>
    </head>
    <body>
        <h1>You have been logged out</h1>
        <div id="centered">
            <p><a href="Login">Login Again</a> | <a href="Welcome">Welcome Page</a></p>
        </div>
    </body>
</html>
