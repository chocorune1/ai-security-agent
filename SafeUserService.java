package com.example.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeUserService {

    public void findUser(Connection conn, String userId)
            throws Exception {

        String sql =
            "SELECT * FROM USERS WHERE USER_ID = ?";

        PreparedStatement stmt =
            conn.prepareStatement(sql);

        stmt.setString(1, userId);

        ResultSet rs = stmt.executeQuery();

        while (rs.next()) {
            System.out.println(
                rs.getString("USER_NAME")
            );
        }
    }
}
