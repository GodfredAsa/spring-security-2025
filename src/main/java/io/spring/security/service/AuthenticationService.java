package io.spring.security.service;

import io.spring.security.client.request.AuthenticationRequest;
import io.spring.security.client.request.RegisterRequest;
import io.spring.security.client.response.ApiResponse;
import io.spring.security.client.response.AuthenticationResponse;
import io.spring.security.entity.Role;
import io.spring.security.entity.User;
import io.spring.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Service
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final Logger LOGGER = LoggerFactory.getLogger(AuthenticationService.class);

    public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public ApiResponse<User> register(RegisterRequest request) {
        repository.findByEmail(request.getEmail()).ifPresent(user -> {
            throw new IllegalStateException("Email already in use");
        });

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        user.setFirstname(request.getFirstname());
        user.setLastname(request.getLastname());
        repository.save(user);
        return new ApiResponse<>(HttpStatus.CREATED.value(), "User created successfully", "Success", user);
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        LOGGER.info("Authenticating user {}", request.getEmail());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return new AuthenticationResponse(jwtToken);
    }


    public User registerAdmin(RegisterRequest request) {
        repository.findByEmail(request.getEmail()).ifPresent(user -> {
            throw new IllegalStateException("Email already in use");
        });

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.ADMIN);
        user.setFirstname(request.getFirstname());
        user.setLastname(request.getLastname());
        repository.save(user);
        return user;
    }

    public User registerFinance(RegisterRequest request) {
        repository.findByEmail(request.getEmail()).ifPresent(user -> {
            throw new IllegalStateException("Email already in use");
        });

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.FINANCE);
        user.setFirstname(request.getFirstname());
        user.setLastname(request.getLastname());
        repository.save(user);
        return user;
    }


//    METHOD LEVEL SECURITY
@PreAuthorize("hasRole('ADMIN')")
public void adminMethod() {
    System.out.println("Admin method accessed");
}

    @PreAuthorize("hasAnyRole('HR', 'FINANCE')")
    public Long getLoan(){
        return  100_000L;
    }

    @PreAuthorize("hasAnyAuthority('HR', 'FINANCE')")
    public Long getLoan(Long amount){
        return  100_000L + amount;
    }

    @PreAuthorize("hasAuthority('HR')")
    public Long getLoan(Long amount, Long initialAmount){
        return  100_000L + amount + initialAmount;
    }

    //    Only allow the login username to access this method
    @PreAuthorize("#username == authentication.principal.username")
    public String getLoans(String username){
        return String.valueOf(100_000L + 100L);
    }

//    POST-AUTHORIZED annotation
    @PostAuthorize("#username == authentication.principal.username")
//    @PostAuthorize("hasAuthority('HR')")
//    @PostAuthorize("hasAnyAuthority('HR', 'FINANCE')")
    public User getUsers(String username){
        return new User();
    }




}