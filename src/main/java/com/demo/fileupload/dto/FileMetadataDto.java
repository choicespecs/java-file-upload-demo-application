package com.demo.fileupload.dto;

import com.demo.fileupload.model.ScanStatus;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * Public projection of {@link com.demo.fileupload.model.FileMetadata} returned by all
 * file endpoints.
 *
 * <p>Intentionally omits internal storage details ({@code filename} UUID and
 * {@code storagePath}) to avoid exposing the on-disk layout to clients. The full
 * {@link com.demo.fileupload.model.User} owner entity is reduced to its username string.
 */
@Data
public class FileMetadataDto {

    /** Database primary key for this file record. */
    private Long id;

    /** Sanitized version of the filename the user originally submitted. */
    private String originalFilename;

    /** Apache Tika-detected MIME type, e.g. {@code "text/plain"} or {@code "application/pdf"}. */
    private String mimeType;

    /** File size in bytes at the time of upload. */
    private long size;

    /**
     * Current antivirus scan result. Set to {@link ScanStatus#CLEAN} immediately after
     * upload (async ClamAV integration is not yet wired). Set to {@link ScanStatus#PENDING}
     * once async scanning is implemented.
     */
    private ScanStatus scanStatus;

    /** Username of the account that uploaded the file. */
    private String ownerUsername;

    /** Timestamp at which the file was uploaded and the metadata row was created. */
    private LocalDateTime createdAt;
}
