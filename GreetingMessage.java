package com.utc.org1.module1;

public class GreetingMessage {

    public String buildGreetingMessage(String[] names) {
        String greeting = "Hello";

        // VIOLATION: (CAST Rule 7954) String concatenation inside the loop
        for (String name : names) {
            greeting += ", " + name;  
        }

        return greeting + "!";
    }
}
