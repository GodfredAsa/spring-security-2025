package io.spring.security.controller;

import io.spring.security.client.request.AuthenticationRequest;
import io.spring.security.client.request.RegisterRequest;
import io.spring.security.client.response.ApiResponse;
import io.spring.security.client.response.AuthenticationResponse;
import io.spring.security.entity.User;
import io.spring.security.repository.UserRepository;
import io.spring.security.service.AuthenticationService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
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
    public ResponseEntity<ApiResponse<User>> register(@RequestBody RegisterRequest request) {
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

    @PreAuthorize("hasRole('FINANCE')")
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

//    METHOD LEVEL SECURITY
    @GetMapping("/admin/{username}")
    public User getAdmin(String username){
        return service.getUsers(username);
    }

    @GetMapping("/admin/loans/{username}")
    public String getLoans(String username){
        return service.getLoans(username);
    }

    @GetMapping("/admin/loans/{amount}/{initialAmount}")
    public Long getLoan(Long amount, Long initialAmount){
        return service.getLoan(amount, initialAmount);
    }


    @GetMapping("/admin/loans/{amount}")
    public Long getLoan(Long amount){
        return amount <= 0 ? service.getLoan() : service.getLoan(amount);
    }


    @GetMapping("/admin/finance/{email}")
    public List<User> getUsersByFinanceEmail(@PathVariable String email) {
        return userRepository.getAllUsersByEmail(email);
    }



}