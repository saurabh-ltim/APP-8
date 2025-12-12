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

public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId"); 
        String newEmail = request.getParameter("newEmail");

        // Use PreparedStatement to prevent SQL injection for storing user data
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {
            pstmt.setString(1, userId);
            pstmt.setString(2, newEmail);
            pstmt.executeUpdate();
            response.getWriter().write("User data stored successfully.<br>");
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return;
        }

        // Use PreparedStatement to prevent SQL injection for fetching user data
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement("SELECT user_id, email FROM user_data WHERE user_id = ?")) {
            pstmt.setString(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (!rs.isBeforeFirst()) { // Check if there are any rows
                    response.getWriter().write("No user found with ID: " + userId + "<br>");
                } else {
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