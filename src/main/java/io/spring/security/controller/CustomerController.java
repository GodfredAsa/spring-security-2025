package io.spring.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CustomerController {
    @GetMapping("/admin")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Hello, Admin!");
    }

    @GetMapping("/hr")
    public ResponseEntity<String> hrEndpoint() {
        return ResponseEntity.ok("Hello, HR!");
    }

    @GetMapping("/finance")
    public ResponseEntity<String> financeEndpoint() {
        return ResponseEntity.ok("Hello, Finance!");
    }
}
