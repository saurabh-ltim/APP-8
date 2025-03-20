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

        // Sanitize inputs IMMEDIATELY upon receiving them
        String safeUserId = StringEscapeUtils.escapeJava(userId);  // Escape for Java context
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
                response.getWriter().write("User ID: " + StringEscapeUtils.escapeHtml4(rs.getString("user_id")) + "<br>"); // Escape HTML in output
                response.getWriter().write("Email: " + StringEscapeUtils.escapeHtml4(rs.getString("email")) + "<br>"); // Escape HTML in output
            }
        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```


Key Improvements:

1. **Immediate Input Sanitization:**  The `userId` and `newEmail` are sanitized using `StringEscapeUtils.escapeJava()` as soon as they are received from the request.  This prevents any unsanitized data from ever being stored in the database.

2. **Prepared Statements (Everywhere):** Both the `INSERT` and `SELECT` queries now use `PreparedStatement`.  This is the most crucial change to prevent SQL injection (both first and second order). Parameterized queries ensure that user input is treated as data, not as part of the SQL command.

3. **Output Encoding (HTML Escaping):**  The values retrieved from the database (`rs.getString(...)`) are escaped using `StringEscapeUtils.escapeHtml4()` before being written to the response. This prevents Cross-Site Scripting (XSS) vulnerabilities.


4. **Dependency:**  The code uses `Apache Commons Text` for escaping. You'll need to add this dependency to your project:

   ```xml
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
       <version>1.10.0</version>  <!-- Or latest version -->
   </dependency>
   ```

5. **Error Handling:**  Added a `return` statement in the `catch` block of the `INSERT` to prevent the code from continuing to the `SELECT` if an error occurs during the insertion.



This revised code effectively prevents second-order SQL injection and addresses other important security considerations like XSS.  It follows OWASP recommendations and best practices for secure coding.