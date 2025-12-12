package com.utc.org1.module1;

import java.util.StringJoiner;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        StringBuilder greetingBuilder = new StringBuilder("Hello");

        if (names != null && names.length > 0) {
            StringJoiner nameJoiner = new StringJoiner(", ");

            for (String name : names) {
                if (name != null && !name.trim().isEmpty()) {
                    nameJoiner.add(name.trim());
                }
            }

            if (nameJoiner.length() > 0) {
                greetingBuilder.append(", ").append(nameJoiner.toString());
            }
        }

        greetingBuilder.append("!");

        return greetingBuilder.toString();
    }
}