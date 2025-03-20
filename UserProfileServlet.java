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

        // Sanitize inputs using escaping. This is suitable for preventing second-order SQL injection where we later use the stored value in a query.
        String safeUserId = StringEscapeUtils.escapeJava(userId);  // Escape for Java strings, crucial for preventing stored XSS too
        String safeNewEmail = StringEscapeUtils.escapeJava(newEmail);


        // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {

            insertStmt.setString(1, safeUserId); // Use parameterized query
            insertStmt.setString(2, safeNewEmail);
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return;
        }

        // Use PreparedStatement to prevent Second Order SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {
            
            selectStmt.setString(1, safeUserId); // Even if the value was sanitized earlier, use a PreparedStatement for every query.

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

1. **Input Sanitization with Escaping:**  The code now uses `StringEscapeUtils.escapeJava()` from Apache Commons Text to sanitize both `userId` and `newEmail`. This escapes special characters, making the strings safe for storage in the database and later retrieval for use in SQL queries.  This is the recommended approach for second-order injection prevention, where escaping prevents the injected code from being interpreted when the data is retrieved later.


2. **Consistent Prepared Statements:** The refactored code uses `PreparedStatement` for *both* the `INSERT` and `SELECT` queries. This is crucial. Even though we've sanitized the input, best practice dictates using parameterized queries *every time* you interact with the database to prevent any possibility of SQL injection.

3. **Dependency:** You'll need to add the Apache Commons Text dependency to your project:

   ```xml
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
       <version>1.10.0</version>  <!-- Or latest version -->
   </dependency>
   ```


Why Escaping for Second-Order Injection?

Second-order injection happens when you sanitize data initially, store it, and then *later* use it in a query without re-sanitizing.  A simple example: imagine you store `O'Reilly` (sanitized to prevent first-order injection).  If you later use this value directly in a query like `SELECT * FROM books WHERE author = '` + storedAuthor + `'`, the single quote will break the query if `storedAuthor` contains `O'Reilly`.  Escaping the value before storing it prevents this.


Why PreparedStatements *Everywhere*?

Prepared statements are the best defense against SQL injection. Even if you've sanitized input, using a prepared statement provides an extra layer of security and ensures you don't accidentally introduce vulnerabilities if you modify the code later.  It's a best practice to *always* use prepared statements, regardless of input sanitization.