package sample;

import java.sql.*;

public class SafeUserService {
    public User findUser(Connection conn, String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE user_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? new User(rs.getString("user_id")) : null;
            }
        }
    }

    static class User {
        User(String id) {}
    }
}
