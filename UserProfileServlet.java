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
import org.apache.commons.text.StringEscapeUtils; // For input sanitization


// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // Sanitize user inputs *before* using them in any database operations
        String userId = StringEscapeUtils.escapeHtml4(request.getParameter("userId"));
        String newEmail = StringEscapeUtils.escapeHtml4(request.getParameter("newEmail"));



        // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {
            
            insertStmt.setString(1, userId);
            insertStmt.setString(2, newEmail);
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important to return after an error to prevent further execution
        }

        // Retrieve user data using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, userId);  // Parameterized query
            try (ResultSet rs = selectStmt.executeQuery()) { 
                while (rs.next()) {
                    response.getWriter().write("User ID: " + rs.getString("user_id") + "<br>");
                    response.getWriter().write("Email: " + rs.getString("email") + "<br>");
                }
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```

Key Changes and Explanations:

1. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize user inputs.  This helps prevent XSS vulnerabilities, which are often exploited in conjunction with second-order SQL injection.  It's crucial to sanitize *before* using the input in database queries.

2. **Prepared Statements (Parameterized Queries):** The most important change is the use of `PreparedStatement` for both the `INSERT` and `SELECT` queries.  This completely separates the SQL code from the user-provided data, eliminating the possibility of SQL injection.  The `?` placeholders are used as parameters, and the `setString()` method safely sets the values.


3. **Dependency:** Make sure to include the Apache Commons Text dependency in your `pom.xml` (if using Maven) or your project's build configuration:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use a recent version -->
</dependency>
```


4. **Error Handling:**  The `return;` statement is added after handling the SQL exception in the `INSERT` block.  This prevents the code from trying to execute the `SELECT` statement if there was an error storing the data.

5. **Try-with-resources:** The code continues to use try-with-resources to ensure that database resources (connections, statements, result sets) are closed properly, even in case of exceptions.



This revised code effectively prevents second-order SQL injection by treating user-supplied data as data, not as part of the SQL command. It also addresses potential XSS vulnerabilities through input sanitization.  Always prioritize parameterized queries or stored procedures when interacting with databases to ensure secure coding practices.