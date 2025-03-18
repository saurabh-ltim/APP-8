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
        
        // Sanitize user inputs  (OWASP recommendation - escape HTML and other special characters)
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
            return; // Important: Exit the method after an error to prevent further execution
        }

        // Retrieve user data using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, userId); // Use the sanitized userId here as well
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


Key improvements:

1. **Prepared Statements:** Both the `INSERT` and `SELECT` queries now use `PreparedStatement` to prevent SQL injection. User-supplied values are treated as parameters, not directly concatenated into the SQL query string.

2. **Input Sanitization:**  The code now uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize user inputs before storing them in the database or using them in queries. This helps prevent cross-site scripting (XSS) attacks.  You might need to add the `commons-text` dependency to your project.  If you don't have a suitable sanitization library yet, encoding HTML entities is a good minimum step.

3. **Error Handling:** Added a `return` statement in the `catch` block of the insert operation to prevent the code from proceeding to the `SELECT` statement if an error occurred during insertion.  This makes the code more robust.

4. **Consistent Sanitization:** The sanitized `userId` is used in both the `INSERT` and the `SELECT` statements, ensuring consistent protection against second-order SQL injection.


To use `StringEscapeUtils`:

1. Add the Apache Commons Text dependency to your `pom.xml` (if you're using Maven):

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- Use the latest version -->
</dependency>
```

2. Import the class: `import org.apache.commons.text.StringEscapeUtils;`


This refactored code effectively addresses the second-order SQL injection vulnerability and also improves the overall security and robustness of the servlet.  Remember to always validate and sanitize all user inputs before using them in database queries or displaying them to users.