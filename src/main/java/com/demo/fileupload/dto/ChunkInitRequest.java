package com.demo.fileupload.dto;

import lombok.Data;

/**
 * Request body for {@code POST /api/files/upload/init}.
 *
 * <p>The client supplies the original filename, total file size in bytes, and the
 * number of chunks it intends to send. The server validates the total size against
 * {@code app.max-large-file-size-mb} and creates a temporary upload session.
 */
@Data
public class ChunkInitRequest {

    /** Original filename (may contain any characters; sanitized server-side). */
    private String filename;

    /** Total size of the complete file in bytes. Used for size-limit enforcement. */
    private long totalSize;

    /**
     * Total number of chunks the client will send.
     * Must equal {@code ceil(totalSize / chunkSize)} as computed by the frontend.
     */
    private int totalChunks;
}
