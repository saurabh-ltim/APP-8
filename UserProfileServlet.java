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

        // Escape user inputs BEFORE storing in the database
        String escapedUserId = StringEscapeUtils.escapeHtml4(userId); 
        String escapedNewEmail = StringEscapeUtils.escapeHtml4(newEmail);


        // Store user-provided data in the database using PreparedStatement
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO user_data (user_id, email) VALUES (?, ?)")) {

            insertStmt.setString(1, escapedUserId);  // Use parameterized query
            insertStmt.setString(2, escapedNewEmail); // Use parameterized query
            insertStmt.executeUpdate();

        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important: Exit the method after an error
        }

        //  Use PreparedStatement to prevent Second Order SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement selectStmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?")) {

            selectStmt.setString(1, escapedUserId); // Parameterized query

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

1. **Escaping Before Database Storage:**  Crucially, the user inputs (`userId`, `newEmail`) are escaped using `StringEscapeUtils.escapeHtml4()` *before* they are stored in the database. This prevents the malicious data from being persistently stored, which is the root of second-order injection.

2. **Consistent Parameterized Queries:**  Both the `INSERT` and `SELECT` statements now use `PreparedStatement`.  This is the most important change.  Parameterized queries completely prevent SQL injection because the user input is treated as data, not as part of the SQL command.

3. **Dependency:** The code now uses `org.apache.commons.text.StringEscapeUtils` for HTML escaping. Make sure you include the `commons-text` dependency in your project (e.g., in your `pom.xml` if using Maven).

4. **Return After Error:**  In the first `try-catch` block, a `return;` statement is added after handling the `SQLException`.  This prevents the code from continuing to the vulnerable `SELECT` statement if there's an error during the `INSERT`.

5. **Try-with-Resources:** The code uses try-with-resources to ensure proper closing of database connections and statements.


This revised code addresses the second-order SQL injection vulnerability by preventing malicious data from being stored in the database in the first place and by using parameterized queries consistently.  It is now much more secure.