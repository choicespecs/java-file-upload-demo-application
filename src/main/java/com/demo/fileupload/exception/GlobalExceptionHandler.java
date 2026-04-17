package com.demo.fileupload.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Centralised exception-to-HTTP-status mapping for all REST controllers.
 *
 * <p>Every handler returns a consistent {@code {"error": "<message>"}} JSON body
 * so that the frontend JavaScript only needs to read {@code response.error} regardless
 * of which exception was thrown. Error messages are intentionally descriptive for
 * client-facing exceptions (file security, bad credentials) and generic for internal
 * errors to avoid leaking implementation details.
 *
 * <p>Handler evaluation order follows Spring's specificity rules — more specific
 * exception types take precedence over {@link RuntimeException}, which is the catch-all.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles content-security violations from the file upload pipeline.
     *
     * @param e the exception carrying the rejection reason (extension, MIME type, zip-bomb)
     * @return HTTP 422 Unprocessable Entity with the rejection message as the error body
     */
    @ExceptionHandler(FileSecurityException.class)
    public ResponseEntity<Map<String, String>> handleFileSecurity(FileSecurityException e) {
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(Map.of("error", e.getMessage()));
    }

    /**
     * Handles business-rule violations such as duplicate usernames or file-size exceeded.
     *
     * @param e the exception with a client-readable message
     * @return HTTP 400 Bad Request
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArg(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    /**
     * Handles failed login attempts with a deliberately vague message to prevent
     * username enumeration (the same response is returned whether the user does not
     * exist or the password is wrong).
     *
     * @param e Spring Security's bad-credentials exception
     * @return HTTP 401 Unauthorized with a generic error message
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(BadCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
    }

    /**
     * Handles login attempts against a locked account.
     *
     * @param e Spring Security's locked-account exception
     * @return HTTP 423 Locked with a message explaining the lockout reason
     */
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Map<String, String>> handleLocked(LockedException e) {
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(Map.of("error", "Account is locked due to too many failed login attempts"));
    }

    /**
     * Handles attempts to access a file that belongs to another user.
     *
     * <p>Spring Security also throws {@link AccessDeniedException} for method-security
     * violations; this handler provides a consistent JSON response for both cases.
     *
     * @param e Spring Security's access-denied exception
     * @return HTTP 403 Forbidden
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDenied(AccessDeniedException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access denied"));
    }

    /**
     * Catch-all handler for unexpected runtime exceptions.
     *
     * <p><strong>Warning:</strong> this returns the raw exception message to the client,
     * which may leak internal details. In production, replace with a generic message and
     * log the exception server-side.
     *
     * @param e any unhandled {@link RuntimeException}
     * @return HTTP 500 Internal Server Error
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleRuntime(RuntimeException e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", e.getMessage()));
    }
}
