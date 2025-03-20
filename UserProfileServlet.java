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


        // Sanitize inputs BEFORE storing them in the database
        String safeUserId = StringEscapeUtils.escapeHtml4(userId);  // Escape HTML characters
        String safeNewEmail = StringEscapeUtils.escapeHtml4(newEmail);

        // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {
            
            insertStmt.setString(1, safeUserId);
            insertStmt.setString(2, safeNewEmail);
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important: exit the method after an error
        }

        // Use PreparedStatement for the SELECT query as well
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, safeUserId); // Use the sanitized userId
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

**Key Changes and Explanations:**

1. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize both `userId` and `newEmail` *before* they are used in any database operations. This is crucial to prevent the injection of malicious HTML or JavaScript that could be stored in the database and later executed when retrieved.  This addresses the root cause of second-order SQL injection.

2. **Prepared Statements (Everywhere):**  The code uses `PreparedStatement` for *both* the `INSERT` and `SELECT` queries. This is the most important change. Prepared statements precompile the SQL query, separating the SQL code from the user-provided data. This prevents the database from interpreting user input as SQL commands.

3. **Dependency:** You'll need to add the Apache Commons Text dependency to your project. In a Maven project, add this to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Or latest version -->
</dependency>
```

4. **Return After Error:**  In the first `try-catch` block, after catching the `SQLException`, the code now includes `return;`. This is important to prevent the code from continuing to execute the vulnerable `SELECT` statement if there was an error during the `INSERT`.

**Why this solution is more robust:**

* **Defense in Depth:**  Even if an attacker manages to bypass the initial input sanitization (though unlikely with proper escaping), the use of prepared statements provides a second layer of defense, preventing the injected code from being executed as SQL.
* **OWASP Compliance:** This approach aligns with OWASP recommendations for preventing SQL injection.  Parameterization (using PreparedStatements) is the preferred method.
* **Maintainability:** Using PreparedStatements makes the code cleaner, easier to read, and less prone to errors.



This revised code addresses the CAST violation and significantly improves the security of the application against second-order SQL injection. Remember to choose the appropriate escaping method (e.g., `escapeHtml4`, `escapeJava`, `escapeEcmaScript`) based on the context where the data will be used after retrieval from the database.  If you are not displaying the data in HTML, you might not need HTML escaping specifically.  However, always use PreparedStatements regardless of the escaping method used.