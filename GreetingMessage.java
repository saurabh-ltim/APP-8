package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        StringBuilder greeting = new StringBuilder("Hello");

        for (String name : names) {
            if (name != null && !name.isEmpty()) {  // Input sanitization: Handle null and empty names
                greeting.append(", ").append(name);
            }
        }

        return greeting.append("!").toString();
    }
}