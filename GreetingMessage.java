package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        StringBuilder greeting = new StringBuilder("Hello");

        for (String name : names) {
            if (name != null) {
                name = name.trim();
                if (!name.isEmpty()) {
                    greeting.append(", ").append(name);
                }
            }
        }

        return greeting.append("!").toString();
    }
}