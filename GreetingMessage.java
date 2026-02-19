package com.utc.org1.module1;

import java.util.StringJoiner;

public class GreetingMessage {

    /**
     * Builds a greeting message from an array of names.
     * Implements proper input sanitization as per OWASP guidelines and
     * uses efficient string concatenation to prevent CAST Rule 7954 violation.
     *
     * @param names An array of names to include in the greeting. Can be null or contain null/empty strings.
     * @return A sanitized greeting message string.
     */
    public String buildGreetingMessage(String[] names) {
        // Handle null or empty names array as an initial sanitization step.
        // Return a default greeting if no names are provided or found.
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        // Use StringJoiner for efficient concatenation of names with a delimiter,
        // preventing repeated String object creation inside the loop (CAST Rule 7954 violation).
        StringJoiner nameListJoiner = new StringJoiner(", ");

        // Iterate through the names array for input sanitization and processing.
        for (String name : names) {
            // OWASP guideline: Validate input and handle potentially malicious data.
            // 1. Handle null names: Treat null as an empty string to avoid NullPointerException.
            if (name != null) {
                // 2. Trim whitespace: Remove leading/trailing whitespace from the name.
                String trimmedName = name.trim();

                // 3. Skip empty names: If the name is empty after trimming, do not include it.
                if (!trimmedName.isEmpty()) {
                    // 4. HTML Encode for XSS prevention:
                    // As per OWASP guidelines (e.g., XSS Prevention Cheat Sheet), if this string
                    // might ever be rendered in an HTML context, it's crucial to HTML-encode
                    // untrusted data. This method applies a basic HTML encoding.
                    String sanitizedName = htmlEncode(trimmedName);
                    nameListJoiner.add(sanitizedName);
                }
            }
        }

        // Build the final greeting message using StringBuilder for efficiency.
        StringBuilder finalMessage = new StringBuilder("Hello");

        // Only append the names part if there are valid names after sanitization.
        if (nameListJoiner.length() > 0) {
            finalMessage.append(", ").append(nameListJoiner.toString());
        }

        // Append the exclamation mark at the end.
        finalMessage.append("!");

        return finalMessage.toString();
    }

    /**
     * Helper method to HTML-encode a string to prevent Cross-Site Scripting (XSS).
     * This method escapes characters that have special meaning in HTML.
     *
     * @param text The string to be HTML-encoded.
     * @return The HTML-encoded string.
     */
    private static String htmlEncode(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder encodedText = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            switch (c) {
                case '&':
                    encodedText.append("&amp;");
                    break;
                case '<':
                    encodedText.append("&lt;");
                    break;
                case '>':
                    encodedText.append("&gt;");
                    break;
                case '"':
                    encodedText.append("&quot;");
                    break;
                case '\'':
                    encodedText.append("&#x27;"); // Apostrophe
                    break;
                case '/':
                    encodedText.append("&#x2F;"); // Solidus (forward slash) is useful in some XSS contexts (e.g., </script>)
                    break;
                default:
                    encodedText.append(c);
            }
        }
        return encodedText.toString();
    }
}