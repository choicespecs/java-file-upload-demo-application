package com.demo.fileupload.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Typed configuration properties for the {@code app.*} namespace.
 *
 * <p>All fields map directly to entries in {@code application.properties}
 * (or profile-specific overrides). Spring Boot binds them automatically via
 * {@link org.springframework.boot.context.properties.ConfigurationProperties}.
 * Lombok {@code @Data} generates getters and setters required by the binding mechanism.
 *
 * <p>Example entries in {@code application.properties}:
 * <pre>
 *   app.jwt-secret=my-secret
 *   app.jwt-expiration-ms=86400000
 *   app.upload-dir=./uploads
 *   app.max-file-size-mb=10
 *   app.max-login-attempts=5
 * </pre>
 */
@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    /**
     * Raw string used to derive the JWT HMAC-SHA256 signing key.
     * The actual key material is a SHA-256 hash of this value, so any string length works.
     * Must be overridden in production via the {@code JWT_SECRET} environment variable
     * or {@code application-prod.properties}.
     */
    private String jwtSecret = "change-this-to-a-long-random-secret-in-production-environments";

    /**
     * JWT token time-to-live in milliseconds.
     * Default is 86 400 000 ms (24 hours).
     */
    private long jwtExpirationMs = 86400000L;

    /**
     * Root directory for uploaded file storage, created automatically if absent.
     * In production this should be an absolute path outside the application root
     * (e.g. {@code /var/uploads/file-upload-demo}).
     */
    private String uploadDir = "./uploads";

    /**
     * Maximum allowed size in megabytes for a single uploaded file.
     * Must be kept in sync with the Spring multipart limits
     * ({@code spring.servlet.multipart.max-file-size}).
     */
    private long maxFileSizeMb = 10;

    /**
     * Number of consecutive failed login attempts before an account is locked.
     * Once locked, the account can only be unlocked manually (no automatic expiry in the
     * current implementation).
     */
    private int maxLoginAttempts = 5;
}
