package io.spring.security.comtroller;

import io.spring.security.client.request.AuthenticationRequest;
import io.spring.security.client.request.RegisterRequest;
import io.spring.security.client.response.AuthenticationResponse;
import io.spring.security.entity.User;
import io.spring.security.repository.UserRepository;
import io.spring.security.service.AuthenticationService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationController {

    @Autowired
    private AuthenticationService service;
    @Autowired private UserRepository userRepository;


    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/register/admin")
    public ResponseEntity<User> registerAdmin(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.registerAdmin(request));
    }

    @PostMapping("/register/finance")
    public ResponseEntity<User> registerFinance(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.registerFinance(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }


    @PreAuthorize("hasRole('ADMIN')")
    public void adminMethod() {
        System.out.println("Admin method accessed");
    }

    @PreAuthorize("hasRole('FINANCE')")
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
       List<User> users = userRepository.findAll();
       return ResponseEntity.ok(users);
    }


}