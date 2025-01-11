package io.spring.security.client.request;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;


public class LoginDto {
    private String email;
    private String password;

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}
