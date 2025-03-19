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

// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("newEmail");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {

            // Use PreparedStatement for both INSERT and SELECT to prevent SQL Injection
            // INSERT statement
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)";
            try (PreparedStatement insertPstmt = conn.prepareStatement(insertQuery)) {
                insertPstmt.setString(1, userId);
                insertPstmt.setString(2, newEmail);
                insertPstmt.executeUpdate();
            }


            // SELECT statement
            String query = "SELECT * FROM user_data WHERE user_id = ?";
            try (PreparedStatement selectPstmt = conn.prepareStatement(query)) {
                selectPstmt.setString(1, userId);  // Parameterized the user ID
                try (ResultSet rs = selectPstmt.executeQuery()) {
                    while (rs.next()) {
                        response.getWriter().write("User ID: " + rs.getString("user_id") + "<br>");
                        response.getWriter().write("Email: " + rs.getString("email") + "<br>");
                    }
                }
            }
        } catch (SQLException e) {
            response.getWriter().write("Error handling user data: " + e.getMessage());
        }
    }
}
```


Key Changes and Explanations:

1. **Prepared Statements (Parameterized Queries):**  The most critical change is replacing `createStatement()` and concatenated SQL strings with `PreparedStatement`. Prepared statements precompile the SQL query and treat user inputs as parameters, effectively preventing SQL injection.

2. **Consistent Parameterization:** Both the `INSERT` and, crucially, the `SELECT` statements now use parameterized queries.  This addresses the second-order SQL injection vulnerability where malicious data inserted into the database could then be used in a subsequent query.

3. **Try-with-resources:** The code uses try-with-resources statements (`try (Connection conn = ...; PreparedStatement pstmt = ...)`), which ensures that database resources (connections, statements, result sets) are closed automatically, even if exceptions occur.  This is best practice for resource management.

4. **Combined try-catch:** I've simplified the error handling by using a single try-catch block to handle potential `SQLExceptions` during both the insert and select operations.

5. **Removed Unnecessary Escaping:** Because prepared statements handle escaping for us, we no longer need any manual escaping or sanitization of user input (unless there are specific application-level validation requirements, like email format checks).


This revised code effectively mitigates the SQL injection vulnerability identified by CAST and adheres to OWASP recommendations.  It also improves code readability and resource management by using try-with-resources.  It's essential to always use parameterized queries when dealing with user-provided data in database interactions.