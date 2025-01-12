package io.spring.security.client.response;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private int status;
    private String message;
    private String reason;
    private T data;

    public ApiResponse(int status, String message, String reason, T data) {
        this.status = status;
        this.message = message;
        this.reason = reason;
        this.data = data;
    }

}
