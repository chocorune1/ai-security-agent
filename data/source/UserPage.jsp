<%@ page language="java" %>

<html>

<body>

<%
    String userName = request.getParameter("userName");
%>

<h1>User Information</h1>

<div>
    <%= userName %>
</div>

<%
    String userId = request.getParameter("userId");

    String sql =
        "SELECT * FROM USERS WHERE USER_ID = '" + userId + "'";
%>

</body>

</html>
