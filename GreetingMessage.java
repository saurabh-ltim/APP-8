package com.utc.org1.module1;

import java.util.StringJoiner;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        StringJoiner joiner = new StringJoiner(", ");
        
        for (String name : names) {
            if (name != null) {
                String trimmedName = name.trim();
                if (!trimmedName.isEmpty()) {
                    joiner.add(trimmedName);
                }
            }
        }

        StringBuilder greetingBuilder = new StringBuilder("Hello");

        if (joiner.length() > 0) {
            greetingBuilder.append(", ").append(joiner.toString());
        }

        greetingBuilder.append("!");
        
        return greetingBuilder.toString();
    }
}