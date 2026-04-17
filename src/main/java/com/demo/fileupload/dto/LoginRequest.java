package com.demo.fileupload.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request body for {@code POST /api/auth/login}.
 *
 * <p>Both fields are validated by Bean Validation before the service layer is invoked.
 * A 400 Bad Request is returned automatically if either field is blank.
 */
@Data
public class LoginRequest {

    /** Username of the account to authenticate. Must not be blank. */
    @NotBlank
    private String username;

    /** Plain-text password to verify against the stored BCrypt hash. Must not be blank. */
    @NotBlank
    private String password;
}
