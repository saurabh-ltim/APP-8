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
        String safeUserId = StringEscapeUtils.escapeSql(userId); // Escape for SQL
        String safeNewEmail = StringEscapeUtils.escapeSql(newEmail);


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

        // Query using PreparedStatement to prevent second-order SQL injection
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

1. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeSql()` from Apache Commons Text to sanitize both `userId` and `newEmail` *before* they are used in any database operations.  This is crucial for preventing both first-order and second-order SQL injection.  Escaping special characters prevents them from being interpreted as SQL commands.  

2. **Prepared Statements (Everywhere):**  The most critical change is the consistent use of `PreparedStatement` for both the `INSERT` and `SELECT` queries.  Prepared statements precompile the SQL query, separating the SQL code from the user-supplied data.  This completely eliminates the risk of SQL injection because the user input is treated as data, not as part of the SQL command.

3. **Dependency:**  You'll need to add the Apache Commons Text dependency to your project. In a Maven project, add this to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Or latest version -->
</dependency>
```


4. **Error Handling:** Added a `return` statement in the `catch` block of the `INSERT` operation to prevent the code from continuing to the `SELECT` statement if there was an error storing the data. This improves the robustness of the code.

Why Escaping AND Prepared Statements?

While prepared statements are generally sufficient to prevent SQL injection, adding input sanitization provides an extra layer of defense. It's a defense-in-depth approach that can protect against vulnerabilities if there's a mistake in how prepared statements are used or other unforeseen issues.  It's a best practice to sanitize all user inputs before using them anywhere in your application.



This improved code effectively mitigates the CAST TQI violation (8420) and follows OWASP recommendations for preventing SQL injection vulnerabilities.  It's essential to sanitize all user inputs before using them in database queries and always use parameterized queries (PreparedStatements).