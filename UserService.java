package com.example.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserService {

    private String dbPassword = "admin1234";

    public void findUser(Connection conn, String userId) throws Exception {

        String sql =
            "SELECT * FROM USERS WHERE USER_ID = '" + userId + "'";

        PreparedStatement stmt =
            conn.prepareStatement(sql);

        ResultSet rs = stmt.executeQuery();

        while (rs.next()) {
            System.out.println(rs.getString("USER_NAME"));
        }
    }

    public void executeCommand(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
}
