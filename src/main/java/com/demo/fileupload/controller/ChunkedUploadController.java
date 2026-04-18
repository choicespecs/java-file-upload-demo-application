package com.demo.fileupload.controller;

import com.demo.fileupload.dto.ChunkInitRequest;
import com.demo.fileupload.dto.ChunkInitResponse;
import com.demo.fileupload.dto.ChunkUploadResponse;
import com.demo.fileupload.dto.FileMetadataDto;
import com.demo.fileupload.service.ChunkedUploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * REST controller for chunked (multi-part) file uploads.
 *
 * <p>All endpoints are under {@code /api/files/upload} and require a valid JWT.
 * This controller handles files too large for the single-request
 * {@code POST /api/files/upload} endpoint in {@link FileController}.
 *
 * <h2>Endpoint sequence</h2>
 * <ol>
 *   <li>{@code POST /api/files/upload/init} — initialise a session, get an {@code uploadId}</li>
 *   <li>{@code POST /api/files/upload/{uploadId}/chunk?chunkIndex=N} — send each chunk</li>
 *   <li>{@code POST /api/files/upload/{uploadId}/complete} — assemble, validate, persist</li>
 *   <li>{@code DELETE /api/files/upload/{uploadId}} — abort and clean up (on error)</li>
 * </ol>
 */
@RestController
@RequestMapping("/api/files/upload")
@RequiredArgsConstructor
public class ChunkedUploadController {

    private final ChunkedUploadService chunkedUploadService;

    /**
     * Initialises a new chunked upload session.
     *
     * @param request body containing {@code filename}, {@code totalSize}, and {@code totalChunks}
     * @param auth    the authenticated principal
     * @return HTTP 200 with a {@link ChunkInitResponse} containing the {@code uploadId}
     * @throws IOException if creating the temporary chunk directory fails
     */
    @PostMapping("/init")
    public ResponseEntity<ChunkInitResponse> init(@RequestBody ChunkInitRequest request,
                                                   Authentication auth) throws IOException {
        String uploadId = chunkedUploadService.initSession(
                auth.getName(), request.getFilename(), request.getTotalSize(), request.getTotalChunks());
        return ResponseEntity.ok(new ChunkInitResponse(uploadId));
    }

    /**
     * Receives and stores a single chunk for an active upload session.
     *
     * @param uploadId   the session identifier from {@link #init}
     * @param chunkIndex zero-based position of this chunk within the complete file
     * @param chunk      the raw chunk bytes as a multipart part
     * @param auth       the authenticated principal
     * @return HTTP 200 with a {@link ChunkUploadResponse} showing progress
     * @throws IOException if writing the chunk to disk fails
     */
    @PostMapping("/{uploadId}/chunk")
    public ResponseEntity<ChunkUploadResponse> uploadChunk(@PathVariable String uploadId,
                                                            @RequestParam int chunkIndex,
                                                            @RequestParam("chunk") MultipartFile chunk,
                                                            Authentication auth) throws IOException {
        return ResponseEntity.ok(
                chunkedUploadService.receiveChunk(uploadId, chunkIndex, chunk, auth.getName()));
    }

    /**
     * Assembles all received chunks, runs security validation, and persists the file.
     *
     * <p>Equivalent in outcome to {@code POST /api/files/upload} but operates on an
     * already-transferred set of chunks rather than a single multipart request.
     *
     * @param uploadId the session identifier
     * @param auth     the authenticated principal
     * @return HTTP 200 with the {@link FileMetadataDto} of the completed upload
     * @throws IOException if file assembly or disk I/O fails
     */
    @PostMapping("/{uploadId}/complete")
    public ResponseEntity<FileMetadataDto> complete(@PathVariable String uploadId,
                                                     Authentication auth) throws IOException {
        return ResponseEntity.ok(chunkedUploadService.completeUpload(uploadId, auth.getName()));
    }

    /**
     * Aborts an in-progress upload and deletes all temporary chunk files.
     *
     * <p>The client should call this on any upload error to avoid leaving orphaned temp files.
     *
     * @param uploadId the session identifier
     * @param auth     the authenticated principal
     * @return HTTP 204 No Content
     * @throws IOException if deleting the temp directory fails
     */
    @DeleteMapping("/{uploadId}")
    public ResponseEntity<Void> abort(@PathVariable String uploadId,
                                       Authentication auth) throws IOException {
        chunkedUploadService.abortUpload(uploadId, auth.getName());
        return ResponseEntity.noContent().build();
    }
}
