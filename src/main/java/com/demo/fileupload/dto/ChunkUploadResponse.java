package com.demo.fileupload.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Response body for {@code POST /api/files/upload/{uploadId}/chunk}.
 *
 * <p>The client can use {@code chunksReceived} and {@code totalChunks} to track
 * upload progress and determine when it is safe to call the complete endpoint.
 */
@Getter
@AllArgsConstructor
public class ChunkUploadResponse {

    /** The upload session identifier, echoed back for client-side correlation. */
    private String uploadId;

    /** Number of distinct chunks received so far for this session. */
    private int chunksReceived;

    /** Total chunks expected, as declared during session initialisation. */
    private int totalChunks;
}
