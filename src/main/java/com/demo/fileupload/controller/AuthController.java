package com.demo.fileupload.controller;

import com.demo.fileupload.dto.AuthResponse;
import com.demo.fileupload.dto.LoginRequest;
import com.demo.fileupload.dto.RegisterRequest;
import com.demo.fileupload.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for authentication endpoints.
 *
 * <p>All paths under {@code /api/auth/**} are publicly accessible (no JWT required),
 * as declared in {@link com.demo.fileupload.config.SecurityConfig}.
 * Both endpoints return a JWT token in the response body on success.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Registers a new user account and immediately issues a JWT.
     *
     * <p>Bean Validation ({@code @Valid}) rejects requests with a blank username,
     * username shorter than 3 characters, blank password, or password shorter than
     * 6 characters before the service layer is reached.
     *
     * @param request validated registration payload containing {@code username} and {@code password}
     * @return HTTP 200 with {@link AuthResponse} containing the JWT token, username, and role
     * @throws IllegalArgumentException (mapped to HTTP 400) if the username is already taken
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Authenticates an existing user and issues a JWT.
     *
     * <p>Failed attempts are counted on the {@link com.demo.fileupload.model.User} entity.
     * After {@code app.max-login-attempts} consecutive failures the account is locked
     * and subsequent attempts return HTTP 423.
     *
     * @param request validated login payload containing {@code username} and {@code password}
     * @return HTTP 200 with {@link AuthResponse} containing the JWT token, username, and role
     * @throws org.springframework.security.authentication.BadCredentialsException
     *         (mapped to HTTP 401) if credentials are invalid
     * @throws org.springframework.security.authentication.LockedException
     *         (mapped to HTTP 423) if the account is locked
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
