package com.demo.fileupload.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * JPA entity representing the metadata record for an uploaded file.
 *
 * <p>The entity deliberately separates two filename concepts:
 * <ul>
 *   <li>{@code filename} — a UUID used as the actual on-disk filename, preventing
 *       path-traversal and filename-collision attacks.</li>
 *   <li>{@code originalFilename} — the sanitized version of the name the user submitted,
 *       stored only in the database for display and for {@code Content-Disposition} headers.</li>
 * </ul>
 *
 * <p>The {@code owner} association is lazy-loaded. Code that needs the owner username
 * must either be inside a transaction or use a DTO projection to avoid
 * {@code LazyInitializationException}.
 */
@Data
@Entity
@Table(name = "file_metadata")
public class FileMetadata {

    /** Auto-generated surrogate primary key. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * UUID-based on-disk filename that prevents path-traversal attacks.
     * Never shown to users; use {@link #originalFilename} for display purposes.
     */
    @Column(nullable = false)
    private String filename;

    /**
     * Sanitized version of the user-supplied filename, stored for display and
     * {@code Content-Disposition} header construction only.
     * Path separators, shell metacharacters, and leading dots are stripped by
     * {@link com.demo.fileupload.service.FileSecurityService#sanitizeFilename}.
     */
    @Column(name = "original_filename", nullable = false)
    private String originalFilename;

    /** Tika-detected MIME type string (e.g. {@code "text/plain"}). May be null for edge cases. */
    @Column(name = "mime_type")
    private String mimeType;

    /** File size in bytes at the time of upload. */
    private long size;

    /** Absolute path to the UUID-named file on the server filesystem. */
    @Column(name = "storage_path")
    private String storagePath;

    /**
     * The user account that uploaded this file.
     * Lazy-fetched to avoid unnecessary joins on list queries.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    /**
     * Current antivirus scan result. Defaults to {@link ScanStatus#PENDING} at entity
     * creation; set to {@link ScanStatus#CLEAN} immediately after upload until async
     * ClamAV scanning is integrated.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "scan_status")
    private ScanStatus scanStatus = ScanStatus.PENDING;

    /**
     * Timestamp at which this record was created.
     * {@code updatable = false} prevents JPA from modifying it on subsequent merges.
     */
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
}
