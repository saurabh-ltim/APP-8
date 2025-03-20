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
import org.apache.commons.text.StringEscapeUtils; // Import for escaping


public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId"); 
        String newEmail = request.getParameter("newEmail");

        // Sanitize inputs  (OWASP Recommendation - Escape)
        String safeUserId = StringEscapeUtils.escapeHtml4(userId);  // HTML escape for storage
        String safeNewEmail = StringEscapeUtils.escapeHtml4(newEmail); // HTML escape for storage



        // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {
            
            insertStmt.setString(1, safeUserId);
            insertStmt.setString(2, safeNewEmail);
            insertStmt.executeUpdate();
            
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return;
        }

        // Query using PreparedStatement to prevent Second Order SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {
            
            selectStmt.setString(1, safeUserId); // Use the sanitized userId! Crucial for preventing 2nd order injection
            ResultSet rs = selectStmt.executeQuery();

            while (rs.next()) {
                response.getWriter().write("User ID: " + rs.getString("user_id") + "<br>");
                response.getWriter().write("Email: " + rs.getString("email") + "<br>");
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```



Key Changes and Explanations:

1. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize both `userId` and `newEmail` *before* they are used in any database operations.  This is crucial for preventing stored XSS vulnerabilities that could lead to Second Order SQL Injection.  Escaping HTML characters is generally a safe approach for storing user-provided data in the database, especially if it might be displayed later.

2. **Prepared Statements (Both INSERT and SELECT):**  The most important change is the consistent use of `PreparedStatement` for both the `INSERT` and, crucially, the `SELECT` query. This completely eliminates the possibility of SQL injection, including second-order injection.  The `?` placeholders are used, and the values are set using `setString()`, ensuring proper escaping by the JDBC driver.

3. **Using Sanitized Input in the `SELECT` Query:** The refactored code uses the *sanitized* `safeUserId` in the `SELECT` statement. This is the essential step to prevent second-order SQL injection.  Even if malicious code was stored in the database, using prepared statements prevents it from being interpreted as SQL.


4. **Dependency:** You'll need to add the Apache Commons Text dependency to your project.  In a Maven project, add this to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use the latest version -->
</dependency>
```




This revised code addresses the CAST violation and follows OWASP recommendations to effectively prevent both first-order and second-order SQL injection vulnerabilities, ensuring a more secure application.