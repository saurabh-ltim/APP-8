```java
package com.utc.org1.module1;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.apache.commons.text.StringEscapeUtils;


public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = StringEscapeUtils.escapeHtml4(request.getParameter("userId")); 
        String newEmail = StringEscapeUtils.escapeHtml4(request.getParameter("newEmail"));

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                pstmt.setString(1, userId);
                pstmt.setString(2, newEmail);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM user_data WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        response.getWriter().write("User ID: " + rs.getString("user_id") + "<br>");
                        response.getWriter().write("Email: " + rs.getString("email") + "<br>");
                    }
                }
            }

        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```