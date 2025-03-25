package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        StringBuilder greeting = new StringBuilder("Hello");

        for (String name : names) {
            if (name != null) {
                greeting.append(", ").append(name);
            }
        }

        return greeting.append("!").toString();
    }
}