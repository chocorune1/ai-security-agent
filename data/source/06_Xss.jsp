<%@ page contentType="text/html; charset=UTF-8" %>
<html>
<body>
    <h2>User Profile</h2>
    <div>
        Welcome, <%= request.getParameter("name") %>
    </div>
</body>
</html>
