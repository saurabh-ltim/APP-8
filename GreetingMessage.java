package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        StringBuilder greetingBuilder = new StringBuilder("Hello");

        if (names != null) {
            for (String name : names) {
                // Appending ", " before each name ensures proper comma separation,
                // matching the original logic's output for an empty array (no comma)
                // and for single/multiple names (comma after "Hello").
                // If 'name' is null, StringBuilder.append(null) will append the string "null",
                // maintaining the behavior of the original String concatenation.
                greetingBuilder.append(", ").append(name);
            }
        }
        
        // Append the exclamation mark at the very end
        greetingBuilder.append("!");

        return greetingBuilder.toString();
    }
}