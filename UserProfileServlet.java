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

        // Sanitize inputs using escaping (best practice for preventing second-order injection)
        String safeUserId = StringEscapeUtils.escapeJava(userId);  // Escape for Java string literals
        String safeNewEmail = StringEscapeUtils.escapeJava(newEmail);

         // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {

            insertStmt.setString(1, safeUserId); // Use sanitized input
            insertStmt.setString(2, safeNewEmail); // Use sanitized input
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return;
        }


        //  Use PreparedStatement to prevent Second Order SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {
             
            selectStmt.setString(1, safeUserId); // IMPORTANT: Use the *sanitized* userId!

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


Key Changes and Explanations:

1. **Escaping for Storage:**  The `StringEscapeUtils.escapeJava()` method from Apache Commons Text is used to escape special characters in the `userId` and `newEmail` *before* they are stored in the database. This prevents the injection of malicious code that might be executed later.  

2. **PreparedStatement for Both INSERT and SELECT:**  The most crucial change is the consistent use of `PreparedStatement` for *both* the `INSERT` and the `SELECT` queries.  This completely eliminates the possibility of SQL injection because the user input is treated as data, not as part of the SQL command.

3. **Using Sanitized Input in the SELECT Query:** This is critical to address second-order injection. Even though you're using a `PreparedStatement` for the `SELECT`, you **must** use the *sanitized* version of `userId` (`safeUserId`) when setting the parameter.  If you used the original `userId` here, the vulnerability would remain.

4. **Dependency:** You'll need to add the Apache Commons Text dependency to your project (e.g., in your `pom.xml` if using Maven):

   ```xml
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
       <version>1.10.0</version>  </dependency>
       <!-- Use the latest version -->
   </dependency>
   ```

Why this is better than encoding:

* **Focus on Prevention:** Escaping is about making data safe for a specific context (like storage in a database).  Prepared statements *prevent* the injection vulnerability entirely.
* **Context-Specific Escaping:**  Different contexts require different escaping rules. Using prepared statements avoids the need to manage these complexities.
* **Less Error-Prone:** It's easy to miss escaping in some parts of your code, reintroducing vulnerabilities. Prepared statements offer more consistent protection.


This revised code demonstrates a robust approach to preventing both first-order and second-order SQL injection vulnerabilities, addressing the CAST TQI violation and following OWASP best practices.