package com.security.shiftmanager.controller;

import com.security.shiftmanager.model.Greeting;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @GetMapping("/hello")
    public Greeting getHelloGreeting() {
        return new Greeting("Hello from Security Shift Manager");
    }
}
