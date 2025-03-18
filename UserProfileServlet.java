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

import org.apache.commons.text.StringEscapeUtils; // Import for escaping HTML


// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("newEmail");

        // Sanitize user inputs to prevent XSS vulnerabilities
        userId = StringEscapeUtils.escapeHtml4(userId);
        newEmail = StringEscapeUtils.escapeHtml4(newEmail);


        // Use PreparedStatement to prevent SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)"; // Parameterized query
            try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                pstmt.setString(1, userId);  // Set parameters safely
                pstmt.setString(2, newEmail);
                pstmt.executeUpdate();       // Execute the query
            } // pstmt is closed automatically here

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important to return here to prevent further execution
        }

        // Use PreparedStatement for the SELECT query as well
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM user_data WHERE user_id = ?"; // Parameterized query
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {  // Execute the query

                    while (rs.next()) {
                        // Escape HTML in the output to prevent XSS
                        String safeUserId = StringEscapeUtils.escapeHtml4(rs.getString("user_id"));
                        String safeEmail = StringEscapeUtils.escapeHtml4(rs.getString("email"));

                        response.getWriter().write("User ID: " + safeUserId + "<br>");
                        response.getWriter().write("Email: " + safeEmail + "<br>");
                    }
                } // rs closed automatically

            } // pstmt closed automatically

        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```


Key Changes and Explanations:

1. **Prepared Statements:** The code now uses `PreparedStatement` for both `INSERT` and `SELECT` queries. This is the most effective way to prevent SQL injection.  Placeholders (`?`) are used instead of directly concatenating user input into the query string.

2. **Parameter Setting:**  The `setString()` method of `PreparedStatement` is used to safely set the values for the placeholders.  The database driver handles escaping special characters, preventing SQL injection.

3. **HTML Escaping (Output Sanitization):** The code uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize the output being written to the response.  This prevents Cross-Site Scripting (XSS) vulnerabilities.  User-supplied data that's retrieved from the database and displayed on the page is escaped to prevent malicious HTML/JavaScript from being executed in the user's browser.  You'll need to add the `commons-text` dependency to your project.


4. **Try-with-resources:** The code uses try-with-resources to ensure that `Connection`, `PreparedStatement`, and `ResultSet` are closed automatically, even if exceptions occur. This prevents resource leaks.

5. **Return after error in INSERT:**  The code now has a `return` statement after handling the `SQLException` in the `INSERT` block. This is crucial. Without the return, the code would continue to the `SELECT` statement, potentially using a corrupted `userId` and leading to unexpected behavior or further vulnerabilities.


By implementing these changes, the code is now protected against second-order SQL injection and XSS vulnerabilities.  Remember to add the Apache Commons Text library to your project's dependencies.  You can do this with Maven or Gradle, depending on your build system. For example, in Maven, add the following dependency to your `pom.xml`:


```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Or latest version -->
</dependency>
```