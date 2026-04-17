package com.demo.fileupload.model;

/**
 * Application roles assigned to user accounts.
 *
 * <p>The {@code ROLE_} prefix is required by Spring Security's {@code hasRole()} expressions
 * and {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}.
 * When calling {@code hasRole("ADMIN")} in security rules, Spring automatically prepends
 * {@code ROLE_}, so both the enum name and the security rule must agree on the suffix.
 *
 * <p>The role is stored as its enum name string in the {@code users.role} column via
 * {@code @Enumerated(EnumType.STRING)}.
 */
public enum Role {

    /** Standard user — can upload, list, download, and delete their own files. */
    ROLE_USER,

    /**
     * Administrator — all {@code ROLE_USER} capabilities plus:
     * <ul>
     *   <li>List all files ({@code GET /api/files/all})</li>
     *   <li>Download, inspect metadata, and delete any user's files</li>
     * </ul>
     */
    ROLE_ADMIN
}
