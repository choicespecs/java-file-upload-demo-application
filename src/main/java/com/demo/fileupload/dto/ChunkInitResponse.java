package com.demo.fileupload.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Response body for {@code POST /api/files/upload/init}.
 *
 * <p>The {@code uploadId} is a UUID that the client must include in every subsequent
 * chunk upload and the final complete call. It also identifies the session for abort.
 */
@Getter
@AllArgsConstructor
public class ChunkInitResponse {

    /** UUID identifying the server-side upload session. */
    private String uploadId;
}
