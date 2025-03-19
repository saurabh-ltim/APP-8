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

        // Sanitize inputs (important even with PreparedStatements for overall security)
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


Key Improvements:

1. **Prepared Statements:** The code now uses `PreparedStatement` for both the INSERT and SELECT queries. This is the most crucial change to prevent SQL injection. User inputs are treated as parameters, not directly concatenated into the SQL query.
2. **Input Sanitization:** Even with prepared statements, it's good practice to sanitize user inputs to prevent other vulnerabilities like XSS. The code uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to escape HTML characters.  You'll need to add the dependency:  `commons-text:commons-text:1.10.0` (or latest) to your project.  Alternatively, you can use other sanitizers depending on your context.
3. **Error Handling:** The `return` statement is added after the error in the `INSERT` block to prevent the code from trying to retrieve data after a failed insertion.
4. **Try-with-resources:** Ensures resources like `Connection`, `PreparedStatement`, and `ResultSet` are closed properly.


This revised code effectively mitigates the second-order SQL injection vulnerability and improves the overall security posture.  Remember to always sanitize inputs and use parameterized queries (PreparedStatements) to interact with databases.