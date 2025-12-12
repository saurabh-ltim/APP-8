package com.utc.org1.module1;

import java.util.Objects;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        // Use StringBuilder for efficient string concatenation, especially inside a loop.
        // This mitigates the CAST Rule 7954 violation.
        StringBuilder greetingBuilder = new StringBuilder("Hello");

        // Implement proper input sanitization and validation as per best practices.
        // Handle null or empty names array gracefully.
        if (names != null && names.length > 0) {
            boolean firstAppendedName = true;
            for (String name : names) {
                // Sanitize individual name:
                // 1. Check for null to prevent NullPointerExceptions.
                // 2. Trim leading/trailing whitespace.
                String sanitizedName = (name != null) ? name.trim() : "";

                // Only append non-empty names after sanitization.
                // This prevents adding ", " for empty or whitespace-only names.
                if (!sanitizedName.isEmpty()) {
                    if (firstAppendedName) {
                        greetingBuilder.append(", ");
                        firstAppendedName = false;
                    } else {
                        greetingBuilder.append(", ");
                    }
                    // Append the sanitized name. No further encoding (like HTML entity encoding)
                    // is applied here as the method returns a plain String. If this string
                    // were to be rendered in an HTML context, HTML encoding should be applied
                    // at the point of output by the consumer of this method.
                    greetingBuilder.append(sanitizedName);
                }
            }
        }

        greetingBuilder.append("!");
        return greetingBuilder.toString();
    }
}