package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        StringBuilder greeting = new StringBuilder("Hello");
        for (int i = 0; i < names.length; i++) {
            String name = names[i];
            if (name != null) {
                greeting.append(", ").append(name);
            }
        }

        return greeting.append("!").toString();
    }
}