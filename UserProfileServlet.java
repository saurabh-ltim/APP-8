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
        
        // Sanitize inputs (important even with prepared statements for other vulnerabilities)
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
            return; // Important to stop processing if insertion fails
        }

        // Retrieve user data using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, userId);  // Parameterized query
            try (ResultSet rs = selectStmt.executeQuery()) {
                while (rs.next()) {
                    response.getWriter().write("User ID: " + StringEscapeUtils.escapeHtml4(rs.getString("user_id")) + "<br>"); //Escape output as well
                    response.getWriter().write("Email: " + StringEscapeUtils.escapeHtml4(rs.getString("email")) + "<br>"); //Escape output as well
                }
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```


Key Improvements:

1. **Prepared Statements:** The code now uses `PreparedStatement` for both the `INSERT` and `SELECT` queries. This is the most crucial change to prevent SQL injection.  User inputs are treated as parameters, not directly concatenated into the SQL query string.

2. **Input Sanitization:**  Uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text (add the dependency: `commons-text:commons-text:1.10.0` to your `pom.xml` if you use Maven, or equivalent for your build system). This helps prevent Cross-Site Scripting (XSS) vulnerabilities, which are important to address even when using parameterized queries.

3. **Output Encoding:**  Added `StringEscapeUtils.escapeHtml4()` to the output to prevent XSS attacks.  Any data retrieved from the database and displayed to the user should be HTML-encoded.


4. **Error Handling:**  The `return` statement is added after the error message in the insertion block. This prevents the code from attempting to execute the `SELECT` statement if the `INSERT` fails, improving the robustness of the code.

5. **Try-with-resources:** Ensures resources like `Connection`, `PreparedStatement`, and `ResultSet` are closed properly, preventing resource leaks.


This revised code effectively mitigates the second-order SQL injection vulnerability and also addresses other potential security issues like XSS.  Remember to always sanitize inputs and encode outputs when dealing with user-supplied data in web applications.