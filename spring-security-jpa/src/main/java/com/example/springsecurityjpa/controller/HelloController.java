package com.example.springsecurityjpa.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class HelloController {

    @GetMapping("/")
    public String hello() {
        return "<h1>Welcome</h1>";
    }

    @GetMapping("user")
    public String user() {
        return "<h1>Welcome user</h1>";
    }

    @GetMapping("/admin")
    public String admin() {
        return "<h1>Welcome admin</h1>";
    }
}
