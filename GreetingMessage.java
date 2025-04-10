package com.utc.org1.module1;

import java.util.Arrays;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        StringBuilder greeting = new StringBuilder("Hello");
        for (String name : Arrays.stream(names).map(this::sanitizeInput).toArray(String[]::new)) {
            greeting.append(", ").append(name);
        }
        greeting.append("!");
        return greeting.toString();
    }

    private String sanitizeInput(String input) {
        // Implement appropriate sanitization based on OWASP guidelines.  
        // Example: remove potentially harmful characters
        return input.replaceAll("[^a-zA-Z0-9 ,.]", ""); 
    }
}