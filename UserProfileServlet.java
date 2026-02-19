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

        // Validate input - basic check for non-null/empty. More robust validation (e.g., regex for email)
        // should be implemented in a real application.
        if (userId == null || userId.trim().isEmpty() || newEmail == null || newEmail.trim().isEmpty()) {
            response.getWriter().write("Error: User ID and Email cannot be empty.");
            return;
        }

        // Mitigated: Using PreparedStatement to prevent SQL injection (both first and second order)
        // Store user-provided data in the database securely
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmtInsert = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {
            
            pstmtInsert.setString(1, userId);
            pstmtInsert.setString(2, newEmail);
            pstmtInsert.executeUpdate();
            
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            // Log the exception for debugging purposes
            getServletContext().log("SQL Error storing user data", e);
            return;
        }

        // Mitigated: Using PreparedStatement to prevent SQL injection when retrieving data
        // Retrieve and display user data
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmtSelect = conn.prepareStatement("SELECT user_id, email FROM user_data WHERE user_id = ?")) {
            
            pstmtSelect.setString(1, userId);
            
            try (ResultSet rs = pstmtSelect.executeQuery()) {
                if (rs.next()) {
                    response.getWriter().write("User ID: " + rs.getString("user_id") + "<br>");
                    response.getWriter().write("Email: " + rs.getString("email") + "<br>");
                } else {
                    response.getWriter().write("User not found after insertion.");
                }
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
            // Log the exception for debugging purposes
            getServletContext().log("SQL Error fetching user data", e);
        }
    }
}