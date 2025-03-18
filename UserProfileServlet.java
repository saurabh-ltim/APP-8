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
import org.apache.commons.text.StringEscapeUtils; // Import for HTML escaping



// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("newEmail");

        // Sanitize user inputs  (Important for preventing XSS and other issues)
        userId = StringEscapeUtils.escapeHtml4(userId);
        newEmail = StringEscapeUtils.escapeHtml4(newEmail);



        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Use PreparedStatement for INSERT query
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                pstmt.setString(1, userId);
                pstmt.setString(2, newEmail);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important: exit the method after an error
        }

        // Use PreparedStatement for SELECT query
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM user_data WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, userId);  // Parameterized query
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        // HTML escape output to prevent XSS vulnerabilities
                        response.getWriter().write("User ID: " + StringEscapeUtils.escapeHtml4(rs.getString("user_id")) + "<br>");
                        response.getWriter().write("Email: " + StringEscapeUtils.escapeHtml4(rs.getString("email")) + "<br>");
                    }
                }
            }

        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```


Key improvements:

* **Prepared Statements:**  Both `INSERT` and `SELECT` queries now use `PreparedStatement`, eliminating the possibility of second-order SQL injection.  User-provided input is treated as data, not as part of the SQL command structure.
* **Input Sanitization:**  Included input sanitization using `StringEscapeUtils.escapeHtml4()` from Apache Commons Text. This is crucial to prevent Cross-Site Scripting (XSS) attacks.  Sanitize all user inputs *before* storing them in the database and also escape data when displaying it back to the user.
* **Try-with-resources:** Ensures resources like `Connection`, `PreparedStatement`, and `ResultSet` are closed properly, preventing resource leaks.
* **Error Handling:**  Added a `return` statement after handling the `SQLException` in the insertion block. This prevents the code from continuing to the `SELECT` statement if an error occurred during the insertion, which could lead to further issues.
* **Dependency:**  You'll need to add the Apache Commons Text dependency to your project.  In a Maven project, add this to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use a recent version -->
</dependency>
```


This refactored code addresses the SQL injection vulnerability and also improves overall security and code quality.  Always prioritize parameterized queries/prepared statements when dealing with user input in database queries.  Don't rely on simple string concatenation or escaping.