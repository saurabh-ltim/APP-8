package com.utc.org1.module1;

import java.util.Arrays;
import java.util.StringJoiner;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        if (names == null || names.length == 0) {
            return "Hello!";
        }

        String[] sanitizedNames = Arrays.stream(names)
                .map(name -> name != null ? name.replaceAll("[^a-zA-Z0-9\\s]", "") : "")
                .toArray(String[]::new);

        StringJoiner joiner = new StringJoiner(", ", "Hello", "!");
        Arrays.stream(sanitizedNames).forEach(joiner::add);
        return joiner.toString();
    }
}