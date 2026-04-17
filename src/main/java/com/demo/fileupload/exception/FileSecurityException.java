package com.demo.fileupload.exception;

/**
 * Thrown by {@link com.demo.fileupload.service.FileSecurityService} when an uploaded file
 * fails any content-security check (blocked extension, executable MIME type, or zip-bomb).
 *
 * <p>Handled by {@link com.demo.fileupload.exception.GlobalExceptionHandler#handleFileSecurity},
 * which maps this exception to HTTP 422 Unprocessable Entity with a JSON body of the form
 * {@code {"error": "<message>"}}.
 *
 * <p>Using a dedicated typed exception (rather than {@code IllegalArgumentException}) allows
 * the global handler to distinguish file security rejections from other bad-input errors and
 * respond with the more precise 422 status.
 */
public class FileSecurityException extends RuntimeException {

    /**
     * Creates a new {@code FileSecurityException} with a human-readable description of the
     * security violation, which is forwarded directly to the client as the error message.
     *
     * @param message description of the security violation (e.g. "File type not allowed: .exe")
     */
    public FileSecurityException(String message) {
        super(message);
    }
}
