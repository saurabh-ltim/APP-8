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
import org.apache.commons.text.StringEscapeUtils; // Import for HTML escaping


// CAST + LLM refactored code
public class UserProfileServlet extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("newEmail");

        // Sanitize inputs (Escape HTML and other special characters)
        userId = StringEscapeUtils.escapeHtml4(userId);
        newEmail = StringEscapeUtils.escapeHtml4(newEmail);


        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Use PreparedStatement for the INSERT query
            String insertQuery = "INSERT INTO user_data (user_id, email) VALUES (?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {
                pstmt.setString(1, userId);
                pstmt.setString(2, newEmail);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            response.getWriter().write("Error storing user data: " + e.getMessage());
            return; // Important: Exit the method after an error to avoid further execution
        }


        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Use PreparedStatement for the SELECT query
            String query = "SELECT * FROM user_data WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, userId);  // Parameterized query
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        // HTML escape output to prevent XSS
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


Key improvements:

* **Prepared Statements:** The code now uses `PreparedStatement` for both `INSERT` and `SELECT` queries. This is the most crucial change to prevent SQL injection.  Placeholders `?` are used, and user inputs are set as parameters, ensuring they are treated as data and not as part of the SQL command.
* **Input Sanitization:**  Uses `StringEscapeUtils.escapeHtml4()` from Apache Commons Text to sanitize user inputs before storing them in the database and before displaying them on the page. This helps prevent Cross-Site Scripting (XSS) vulnerabilities.  Make sure to include the `commons-text` dependency in your project (e.g., in your `pom.xml` if you're using Maven).
* **Error Handling:**  Added a `return` statement after the error in the `INSERT` block to prevent the code from continuing to the `SELECT` block if there's a problem storing the data.
* **Output Encoding (HTML Escaping):**  Crucially, the output is now HTML-encoded using `StringEscapeUtils.escapeHtml4()`  before being written to the response. This protects against XSS attacks where malicious scripts could be injected via the stored user data.



To add the Apache Commons Text dependency to your `pom.xml` (if using Maven):

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  </dependency>
```  (Or use the latest version).


This revised code significantly reduces the risk of SQL injection and XSS vulnerabilities, making the application much more secure.