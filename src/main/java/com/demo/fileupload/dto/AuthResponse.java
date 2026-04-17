package com.demo.fileupload.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Response body returned by successful {@code /api/auth/register} and
 * {@code /api/auth/login} calls.
 *
 * <p>The client stores {@code token} in {@code localStorage} and includes it in every
 * subsequent API request as {@code Authorization: Bearer <token>}.
 */
@Data
@AllArgsConstructor
public class AuthResponse {

    /** Signed JWT the client must present as a bearer token on subsequent requests. */
    private String token;

    /** Username of the authenticated account, stored in {@code localStorage} for display. */
    private String username;

    /**
     * Role name (e.g. {@code "ROLE_USER"} or {@code "ROLE_ADMIN"}) stored in
     * {@code localStorage} for conditional UI rendering (not enforced client-side).
     */
    private String role;
}
