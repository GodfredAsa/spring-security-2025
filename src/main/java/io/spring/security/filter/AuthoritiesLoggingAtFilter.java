package io.spring.security.filter;

import io.spring.security.service.AuthenticationService;
import jakarta.servlet.*;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.stream.Collectors;

@Slf4j
public class AuthoritiesLoggingAtFilter implements Filter {
    private final Logger LOGGER = LoggerFactory.getLogger(AuthoritiesLoggingAtFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Retrieve the current authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            // Log the authorities
            String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(", "));
            LOGGER.info("AuthoritiesLoggingAtFilter: User Authorities: {}", authorities);
        } else {
            LOGGER.info("AuthoritiesLoggingAtFilter: No authenticated user.");
        }

        chain.doFilter(request, response);

    }
}