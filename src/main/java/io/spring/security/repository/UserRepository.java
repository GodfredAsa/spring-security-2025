package io.spring.security.repository;

import io.spring.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {


    Optional<User> findByEmail(String email);

//    @PreAuthorize("hasRole('ADMIN')")
//    List<User> getAllUsers();

//    GET ALL USERS AND ENSURE THE LOGIN EMAIL MATCHES THE REQUESTER.
    @PostAuthorize("#email == authentication.principal.email")
    List<User> getAllUsersByEmail(String email);
}
