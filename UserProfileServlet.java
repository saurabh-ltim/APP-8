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
import org.apache.commons.text.StringEscapeUtils; // Import for proper sanitization


public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId"); 
        String newEmail = request.getParameter("newEmail");

        // Sanitize inputs using a strong escaping library like Apache Commons Text
        String safeUserId = StringEscapeUtils.escapeHtml4(userId);
        String safeNewEmail = StringEscapeUtils.escapeHtml4(newEmail);



        // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {

            insertStmt.setString(1, safeUserId);  // Use parameterized query for insert
            insertStmt.setString(2, safeNewEmail);
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return;
        }

        // Query using PreparedStatement to prevent Second Order SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

             selectStmt.setString(1, safeUserId); // Parameterized query is crucial here!
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

1. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize both `userId` and `newEmail`. This is crucial to prevent any malicious code injected via these parameters from being interpreted as HTML or SQL.  While `escapeHtml4` primarily addresses HTML escaping, in this context, it effectively neutralizes characters that could be used for SQL injection within string literals.  For more targeted SQL escaping, consider using a dedicated SQL escaping function if your database driver or framework provides one.

2. **Prepared Statements (Parameterized Queries):** The MOST important change is the consistent use of `PreparedStatement` for both the `INSERT` and `SELECT` queries.  This is the **primary defense against SQL injection**. Prepared statements precompile the SQL query, treating user inputs as data rather than part of the query structure, effectively preventing SQL injection vulnerabilities.

3. **Dependency:**  You need to add the Apache Commons Text dependency to your project.  In a Maven project, add this to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use the latest version -->
</dependency>
```

**Why this is more secure:**

* **Prepared Statements:** By using `PreparedStatement`,  the user-supplied input is treated as data, not executable code. This eliminates the possibility of malicious input altering the SQL query's structure.

* **Input Sanitization:**  Sanitizing inputs provides an extra layer of defense, particularly against cross-site scripting (XSS) attacks, where malicious HTML/JavaScript could be stored in the database and then rendered in the browser.



This revised code effectively mitigates the second-order SQL injection vulnerability and improves overall security.  Always prioritize using parameterized queries (`PreparedStatement`) as the primary defense against SQL injection. Input sanitization serves as an additional layer of protection for other web vulnerabilities.