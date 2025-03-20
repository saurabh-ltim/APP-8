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

        // Sanitize inputs before using them in ANY query
        String safeUserId = StringEscapeUtils.escapeJava(userId);  // Escape for Java String contexts
        String safeNewEmail = StringEscapeUtils.escapeJava(newEmail);


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

        // Query using PreparedStatement to prevent Second Order SQL Injection
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


Key Changes and Explanations:

1. **Input Sanitization:** The code now uses `StringEscapeUtils.escapeJava()` from Apache Commons Text to sanitize both `userId` and `newEmail` *before* they are used in any database operations.  This escaping is crucial to prevent injection attacks, even if the data has been stored in the database.  Escaping for Java String contexts helps prevent issues if the data is later used in other parts of the application.

2. **Prepared Statements (Everywhere):**  Both the `INSERT` and `SELECT` statements are now constructed using `PreparedStatement`. This is the most important change to prevent SQL injection.  Prepared statements separate the SQL code from the data, making it impossible for malicious input to be interpreted as SQL commands.

3. **Dependency:** You'll need to add the Apache Commons Text dependency to your project. In a Maven project, add this to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use the latest version -->
</dependency>
```

4. **Return After Error:** In the first `try-catch` block, a `return` statement has been added after the error handling. This prevents the code from continuing to execute the vulnerable `SELECT` statement if there's an error during the `INSERT`.

5. **Consistent Sanitization:** Critically, the sanitized `safeUserId` is used consistently throughout the code, both for inserting and retrieving data. This ensures complete protection against second-order SQL injection.


Why escaping and Prepared Statements are used together:

* **Defense in Depth:** While Prepared Statements are the primary defense against SQL injection, escaping provides an additional layer of protection, especially in cases where data might be used in contexts other than database queries.

* **Context-Specific Escaping:** Different contexts require different escaping methods. `StringEscapeUtils.escapeJava()` ensures the data is safe for use within Java strings, which could be important if you later use the retrieved data in other parts of your application.  You would use different escaping functions (e.g., `escapeHtml4()`) if you were displaying the data directly in HTML.


This revised code comprehensively addresses the second-order SQL injection vulnerability by sanitizing all user inputs before they are used in database queries and consistently using parameterized queries (PreparedStatements) for all database interactions.  This is the recommended and most secure way to prevent this type of vulnerability.