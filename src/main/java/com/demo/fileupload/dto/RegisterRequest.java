package com.demo.fileupload.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request body for {@code POST /api/auth/register}.
 *
 * <p>Constraints are validated by Bean Validation before the service layer is invoked.
 * The same constraints are mirrored in the HTML registration form for immediate
 * client-side feedback, but server-side validation is the authoritative check.
 */
@Data
public class RegisterRequest {

    /**
     * Desired username. Must be 3–50 characters, not blank.
     * Stored as-is (no normalisation); uniqueness is enforced by a unique DB constraint.
     */
    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    /**
     * Plain-text password. Must be 6–100 characters, not blank.
     * BCrypt-hashed before storage; the raw value is never persisted.
     */
    @NotBlank
    @Size(min = 6, max = 100)
    private String password;
}
