package sample;

import java.sql.*;

public class SqlInjectionExample {
    public User findUser(Connection conn, String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE user_id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next() ? new User(rs.getString("user_id")) : null;
    }

    static class User {
        User(String id) {}
    }
}
