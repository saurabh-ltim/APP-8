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

import org.apache.commons.text.StringEscapeUtils; // Import for input sanitization

// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Sanitize user inputs using StringEscapeUtils from Apache Commons Text
        String userId = StringEscapeUtils.escapeHtml4(request.getParameter("userId")); 
        String newEmail = StringEscapeUtils.escapeHtml4(request.getParameter("newEmail"));


        // Use PreparedStatement to prevent SQL injection for INSERT
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {

            insertStmt.setString(1, userId);
            insertStmt.setString(2, newEmail);
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important to return after an error to prevent further execution
        }

        // Use PreparedStatement to prevent SQL injection for SELECT
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, userId); // Set the parameter value safely
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

1. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeHtml4()` from the Apache Commons Text library to sanitize user inputs (`userId` and `newEmail`). This helps prevent XSS vulnerabilities if the data is later displayed in a web page.  While not strictly part of preventing SQL injection, it's a crucial security practice to sanitize all user inputs.

2. **Prepared Statements:**  The code uses `PreparedStatement` for both the `INSERT` and `SELECT` queries. This is the most effective way to prevent SQL injection.  Prepared statements precompile the SQL query and treat user inputs as parameters, preventing them from being interpreted as SQL code.

3. **Parameter Setting:**  Placeholders (`?`) are used in the SQL query string, and the `setString()` method of the `PreparedStatement` is used to set the values of the parameters safely.  This separates the SQL code from the user-provided data.

4. **Error Handling:**  The code includes a `return` statement after handling the `SQLException` in the insertion block. This prevents the code from continuing to the `SELECT` statement if there's an error during insertion. This is a good practice to avoid unexpected behavior.

5. **Dependency:**  You'll need to add the Apache Commons Text dependency to your project.  For Maven, add the following to your `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use the latest version -->
</dependency>
```


By implementing these changes, the code is now protected against second-order SQL injection vulnerabilities.  The user input stored in the database is sanitized, and it's treated as data, not executable code, when used in subsequent queries.