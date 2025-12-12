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

        // Implement proper input sanitization as per OWASP guidelines.
        // This includes using Prepared Statements for SQL injection prevention
        // and performing input validation for data integrity and defense-in-depth.

        // Basic input validation: check for null/empty and reasonable length limits.
        // For 'newEmail', a basic regex check for email format.
        if (userId == null || userId.trim().isEmpty() || userId.length() > 50) {
            response.getWriter().write("Invalid User ID. User ID cannot be empty and must be less than 50 characters.");
            return;
        }
        // A more robust email validation might be needed depending on specific requirements.
        // This regex is a simple example for basic format checking.
        if (newEmail == null || newEmail.trim().isEmpty() || newEmail.length() > 100 || !newEmail.matches("^[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,6}$")) {
            response.getWriter().write("Invalid Email. Email cannot be empty, must be less than 100 characters, and in a valid format.");
            return;
        }

        // Store user-provided data in the database using PreparedStatement
        // This prevents SQL Injection by separating the SQL command from the data.
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {
            
            pstmt.setString(1, userId);
            pstmt.setString(2, newEmail);
            pstmt.executeUpdate();
            
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            // It's good practice to log the full stack trace for debugging purposes
            System.err.println("SQL Exception storing user data for userId: " + userId + " - " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Fetch user data using PreparedStatement to prevent SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement("SELECT user_id, email FROM user_data WHERE user_id = ?")) {
            
            pstmt.setString(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (!rs.isBeforeFirst()) { // Check if the ResultSet is empty
                    response.getWriter().write("No user data found for User ID: " + userId + "<br>");
                } else {
                    while (rs.next()) {
                        // When outputting data retrieved from the database,
                        // consider HTML encoding to prevent Cross-Site Scripting (XSS) if this output
                        // is rendered directly into an HTML page.
                        // For this specific SQL Injection fix, PreparedStatement is the primary concern.
                        response.getWriter().write("User ID: " + rs.getString("user_id") + "<br>");
                        response.getWriter().write("Email: " + rs.getString("email") + "<br>");
                    }
                }
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
            // Log the exception for debugging purposes
            System.err.println("SQL Exception fetching user data for userId: " + userId + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
}