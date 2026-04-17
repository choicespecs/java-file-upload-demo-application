package com.demo.fileupload.model;

/**
 * Antivirus scan status for an uploaded file.
 *
 * <p>The intended lifecycle is: {@code PENDING} (awaiting async scan) →
 * {@code CLEAN} or {@code INFECTED} (scan completed) → {@code FAILED} (scan error).
 *
 * <p>Currently all files are set to {@link #CLEAN} synchronously at upload time because
 * the async ClamAV integration is not yet implemented. The {@code scan/{id}} endpoint
 * exists as a stub for wiring the real scan; see
 * {@link com.demo.fileupload.controller.FileController#rescan}.
 *
 * <p>Stored as a string in the {@code file_metadata.scan_status} column via
 * {@code @Enumerated(EnumType.STRING)}.
 */
public enum ScanStatus {

    /** File has been received but not yet scanned (initial state for async scanning). */
    PENDING,

    /** Antivirus scan completed — no threats detected. */
    CLEAN,

    /** Antivirus scan completed — malware or threat detected. */
    INFECTED,

    /** Antivirus scan could not be completed due to an error. */
    FAILED
}
