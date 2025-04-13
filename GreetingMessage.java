package com.utc.org1.module1;

import java.util.Arrays;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        StringBuilder greeting = new StringBuilder("Hello");
        for (String name : Arrays.stream(names).map(s -> s == null ? "" : s.trim()).toArray(String[]::new)) {
            greeting.append(", ").append(name);
        }
        return greeting.append("!").toString();
    }
}