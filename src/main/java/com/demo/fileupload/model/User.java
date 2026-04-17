package com.demo.fileupload.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * JPA entity representing a registered user account.
 *
 * <p>Credentials and role are managed by the auth layer ({@link com.demo.fileupload.service.AuthService}).
 * Lockout state ({@code accountLocked}, {@code failedAttempts}) is maintained by
 * {@code AuthService.login} and propagated to Spring Security via
 * {@link com.demo.fileupload.security.UserDetailsServiceImpl}.
 *
 * <p>The {@code password} field stores a BCrypt hash; the plain-text password is never persisted.
 */
@Data
@Entity
@Table(name = "users")
public class User {

    /** Auto-generated surrogate primary key. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Unique login name. 3–50 characters as enforced by {@link com.demo.fileupload.dto.RegisterRequest}.
     * The unique constraint is enforced at both the application layer (duplicate check in
     * {@code AuthService.register}) and the database column constraint.
     */
    @Column(unique = true, nullable = false, length = 50)
    private String username;

    /**
     * BCrypt hash of the user's password.
     * Column length 100 accommodates standard BCrypt output (~60 chars) with headroom.
     */
    @Column(nullable = false, length = 100)
    private String password;

    /**
     * Role assigned to this account. Stored as the enum name string.
     * Defaults to {@link Role#ROLE_USER}; admins must be promoted directly in the database.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role = Role.ROLE_USER;

    /**
     * Whether this account has been locked due to too many failed login attempts.
     * Once {@code true}, the account cannot be used until manually unlocked.
     * Propagated to {@code UserDetails.isAccountNonLocked()} by
     * {@link com.demo.fileupload.security.UserDetailsServiceImpl}.
     */
    @Column(name = "account_locked")
    private boolean accountLocked = false;

    /**
     * Number of consecutive failed login attempts since the last successful login.
     * Reset to 0 on any successful authentication.
     * When this reaches {@code app.max-login-attempts}, {@code accountLocked} is set to {@code true}.
     */
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    /**
     * Timestamp of the most recent successful login.
     * Updated by {@code AuthService.login} on success; {@code null} if the user has never
     * logged in after registration.
     */
    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    /**
     * Timestamp at which this account was created.
     * {@code updatable = false} ensures JPA never overwrites it on subsequent merges.
     */
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
}
