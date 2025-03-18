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

        // Sanitize inputs to prevent XSS (Cross-Site Scripting)
        userId = StringEscapeUtils.escapeHtml4(userId);
        newEmail = StringEscapeUtils.escapeHtml4(newEmail);


        // Use PreparedStatement for the INSERT query to prevent SQL injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {

            insertStmt.setString(1, userId);
            insertStmt.setString(2, newEmail);
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Stop processing if data storage fails
        }

        // Use PreparedStatement for the SELECT query to prevent Second Order SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, userId); // Use parameterized query
            ResultSet rs = selectStmt.executeQuery();

            while (rs.next()) {
                // Escape HTML in output to prevent XSS
                String escapedUserId = StringEscapeUtils.escapeHtml4(rs.getString("user_id"));
                String escapedEmail = StringEscapeUtils.escapeHtml4(rs.getString("email"));


                response.getWriter().write("User ID: " + escapedUserId + "<br>");
                response.getWriter().write("Email: " + escapedEmail + "<br>");
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```


Key Changes and Explanations:

1. **Prepared Statements:** The code now uses `PreparedStatement` for both the `INSERT` and `SELECT` queries.  This is the most crucial change to prevent SQL injection (both first-order and second-order). Prepared statements precompile the SQL query, treating user inputs as parameters rather than part of the SQL code itself.  This prevents malicious code injection.

2. **Input Sanitization (XSS Prevention):** The code uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize user inputs (`userId` and `newEmail`) before storing them in the database and before displaying them back to the user.  This helps prevent Cross-Site Scripting (XSS) attacks.  You'll need to add the `commons-text` dependency to your project:

   ```xml
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
       <version>1.10.0</version>  <!-- Or latest version -->
   </dependency>
   ```

3. **Error Handling:**  The code now includes a `return` statement after writing the error message in the `catch` block of the `INSERT` section. This prevents the code from continuing to execute the vulnerable `SELECT` statement if there was an error storing the data, which could potentially expose other vulnerabilities.

4. **Comments:**  Comments have been added to explain the changes and the purpose of using prepared statements and input sanitization.


By implementing these changes, the code is now significantly more secure and resistant to both SQL injection and XSS vulnerabilities.  Always prioritize using parameterized queries/prepared statements whenever dealing with user-supplied data in database interactions.