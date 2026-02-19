package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        StringBuilder sb = new StringBuilder("Hello");

        if (names != null) {
            for (String name : names) {
                sb.append(", ").append(sanitize(name));
            }
        }

        sb.append("!");
        return sb.toString();
    }

    /**
     * Sanitizes the input string to prevent common injection attacks (e.g., XSS)
     * and ensures safe display, following OWASP guidelines for output encoding.
     *
     * @param input The string to sanitize.
     * @return The sanitized string.
     */
    private String sanitize(String input) {
        if (input == null) {
            return ""; // Treat null input as an empty string.
        }

        String sanitized = input.trim(); // Trim leading/trailing whitespace

        // Basic HTML entity escaping for output encoding (XSS prevention).
        // This is a common recommendation when displaying user-controlled data.
        sanitized = sanitized.replace("&", "&amp;");   // Must be first
        sanitized = sanitized.replace("<", "&lt;");
        sanitized = sanitized.replace(">", "&gt;");
        sanitized = sanitized.replace("\"", "&quot;");
        sanitized = sanitized.replace("'", "&#x27;"); // For single quotes
        sanitized = sanitized.replace("/", "&#x2F;"); // For forward slash, optional but good practice

        return sanitized;
    }
}