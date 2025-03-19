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


// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("newEmail");

        // Sanitize inputs using escaping  (Primary Defense)
        String safeUserId = StringEscapeUtils.escapeHtml4(userId);  // Escape for HTML context (if userId is displayed)
        String safeNewEmail = StringEscapeUtils.escapeHtml4(newEmail);


        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Use PreparedStatement for parameterized queries (Main defense against SQL Injection)
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                pstmt.setString(1, safeUserId); 
                pstmt.setString(2, safeNewEmail);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important: Exit the method after an error to prevent further execution
        }


        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Use PreparedStatement for the SELECT query as well
            String query = "SELECT * FROM user_data WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, safeUserId); // Use the sanitized userId
                try (ResultSet rs = pstmt.executeQuery()) {

                    while (rs.next()) {

                        // Escape data retrieved from the database before displaying it on the webpage.
                        String escapedUserId = StringEscapeUtils.escapeHtml4(rs.getString("user_id"));
                        String escapedEmail = StringEscapeUtils.escapeHtml4(rs.getString("email"));

                        response.getWriter().write("User ID: " + escapedUserId + "<br>");
                        response.getWriter().write("Email: " + escapedEmail + "<br>");
                    }
                }
            }

        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```

**Key Improvements:**

1. **Parameterized Queries (PreparedStatement):** This is the most crucial change.  PreparedStatements precompile the SQL query, treating user inputs as parameters rather than part of the query itself. This prevents SQL injection vulnerabilities effectively.

2. **Input Sanitization (Escaping):**  Using `StringEscapeUtils.escapeHtml4()` from Apache Commons Text (or similar library) ensures that any HTML special characters in the user input are escaped, preventing XSS (Cross-Site Scripting) vulnerabilities if you are displaying the data back to the user in an HTML context.

3. **Consistent Sanitization:** Sanitize user input *before* storing it in the database.  This prevents potential issues if the data is used in other parts of your application or displayed in different contexts.

4. **Dependency:** You will need to add the Apache Commons Text dependency to your project:

   ```xml
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
       <version>1.10.0</version>  <!-- Or latest version -->
   </dependency>
   ```


By combining parameterized queries and appropriate escaping, you effectively mitigate the second-order SQL injection vulnerability and improve the overall security of your web application.  Always sanitize on output as well, especially when dealing with data that has been stored in the database (as shown in the refactored code when displaying the results).  This adds an extra layer of defense.