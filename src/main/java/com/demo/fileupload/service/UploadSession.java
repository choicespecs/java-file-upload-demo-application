package com.demo.fileupload.service;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds in-memory state for an active chunked upload session.
 *
 * <p>Instances are created by {@link ChunkedUploadService#initSession} and stored in a
 * {@link ConcurrentHashMap} keyed by {@code uploadId}. They are removed when the upload
 * completes successfully or is aborted.
 *
 * <p>{@code receivedChunks} uses a concurrent set so that concurrent chunk uploads from
 * a single session do not require external synchronisation on the set itself.
 */
public class UploadSession {

    private final String uploadId;
    private final String username;
    private final String originalFilename;
    private final int totalChunks;
    private final long totalSize;

    /** Tracks which chunk indices have been written to disk. Thread-safe. */
    private final Set<Integer> receivedChunks = ConcurrentHashMap.newKeySet();

    /** Temporary directory under {@code {upload-dir}/chunks/{uploadId}/} for chunk files. */
    private final Path tempDir;

    private final Instant createdAt;

    public UploadSession(String uploadId, String username, String originalFilename,
                         int totalChunks, long totalSize, Path tempDir) {
        this.uploadId = uploadId;
        this.username = username;
        this.originalFilename = originalFilename;
        this.totalChunks = totalChunks;
        this.totalSize = totalSize;
        this.tempDir = tempDir;
        this.createdAt = Instant.now();
    }

    public String getUploadId() { return uploadId; }
    public String getUsername() { return username; }
    public String getOriginalFilename() { return originalFilename; }
    public int getTotalChunks() { return totalChunks; }
    public long getTotalSize() { return totalSize; }
    public Set<Integer> getReceivedChunks() { return receivedChunks; }
    public Path getTempDir() { return tempDir; }
    public Instant getCreatedAt() { return createdAt; }

    /** Returns {@code true} when all expected chunks have been received. */
    public boolean isComplete() {
        return receivedChunks.size() == totalChunks;
    }
}
