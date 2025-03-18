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
import org.apache.commons.text.StringEscapeUtils; // For HTML escaping


// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("newEmail");

        // Sanitize inputs (Important! Especially before storing in the DB)
        userId = StringEscapeUtils.escapeHtml4(userId); // Prevent XSS when displaying later
        newEmail = StringEscapeUtils.escapeHtml4(newEmail); // Prevent XSS


        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Use PreparedStatement for INSERT
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                pstmt.setString(1, userId);
                pstmt.setString(2, newEmail);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important: Stop processing if data storage fails
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
           // Use PreparedStatement for SELECT
            String query = "SELECT * FROM user_data WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {

                        // HTML escape output to prevent XSS
                        String safeUserId = StringEscapeUtils.escapeHtml4(rs.getString("user_id"));
                        String safeEmail = StringEscapeUtils.escapeHtml4(rs.getString("email"));


                        response.getWriter().write("User ID: " + safeUserId  + "<br>");
                        response.getWriter().write("Email: " + safeEmail + "<br>");
                    }
                }
            }

        } catch (SQLException e) {
            response.getWriter().write("Error fetching user data: " + e.getMessage());
        }
    }
}
```


Key Improvements:

1. **Prepared Statements:**  The code now uses `PreparedStatement` for both the `INSERT` and `SELECT` queries. This is the most crucial change to prevent SQL injection.  Placeholders `?` are used, and the values are set separately, preventing user input from being interpreted as SQL code.

2. **Input Sanitization:** The code uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize user inputs (`userId` and `newEmail`) before storing them in the database and *also before displaying them in the HTML response*.  This prevents Cross-Site Scripting (XSS) attacks.  You'll need to add the dependency:
   ```xml
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
       <version>1.10.0</version>  <!-- Or latest version -->
   </dependency>
   ```

3. **Error Handling:** The `return;` statement after the `catch` block in the `INSERT` section ensures that the code doesn't proceed to the `SELECT` statement if there's an error storing the data.  This prevents potential issues where the application might try to retrieve data that hasn't been correctly inserted.

4. **Output Encoding (XSS Prevention):**  The code now uses `StringEscapeUtils.escapeHtml4()` to encode data retrieved from the database *before* it is written to the HTTP response. This prevents stored XSS vulnerabilities where malicious code injected into the database could be executed in the user's browser.




This revised code effectively mitigates the second-order SQL injection vulnerability and also addresses potential XSS vulnerabilities, making it significantly more secure.  Always prioritize using parameterized queries/prepared statements when interacting with databases.  Input validation and output encoding are also essential security best practices.