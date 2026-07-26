package com.cybershield.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * LoginRequest — the body the client sends to POST /api/auth/login
 *
 * Example JSON:
 * {
 *   "username": "santhosh",
 *   "password": "MyPassword123"
 * }
 */
@Data
public class LoginRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 100, message = "Username must be 3–100 characters")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
}
