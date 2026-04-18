package com.demo.fileupload.service;

import com.demo.fileupload.config.AppProperties;
import com.demo.fileupload.dto.ChunkUploadResponse;
import com.demo.fileupload.dto.FileMetadataDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.*;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages multi-part (chunked) file uploads for files that exceed the regular
 * single-request size limit.
 *
 * <h2>Session lifecycle</h2>
 * <ol>
 *   <li>{@link #initSession} — validates total size, creates a temp directory under
 *       {@code {upload-dir}/chunks/{uploadId}/}, and registers an {@link UploadSession}
 *       in the in-memory session map.</li>
 *   <li>{@link #receiveChunk} — writes each incoming chunk to
 *       {@code {tempDir}/{chunkIndex}} and records it in {@code receivedChunks}.</li>
 *   <li>{@link #completeUpload} — once all chunks are received, assembles them in
 *       order into a single UUID-named file under {@code upload-dir}, runs all security
 *       validation via {@link FileSecurityService#validateAndGetMimeType(Path, String)},
 *       then delegates to {@link FileService#persistAssembledFile} for DB persistence.</li>
 *   <li>{@link #abortUpload} — cleans up the temp directory and removes the session.
 *       Called explicitly by the client or internally on assembly/validation failure.</li>
 * </ol>
 *
 * <h2>Session storage</h2>
 * <p>Sessions are held in a {@link ConcurrentHashMap}. This is sufficient for a single
 * JVM instance. A production deployment behind a load balancer would need a shared
 * store (Redis, DB) so all nodes can see the same session. Stale sessions (no activity
 * for an extended period) are not automatically evicted in the current implementation;
 * a scheduled cleanup job should be added for production use.
 */
@Service
@RequiredArgsConstructor
public class ChunkedUploadService {

    private final FileService fileService;
    private final FileSecurityService fileSecurityService;
    private final AppProperties appProperties;

    /** In-memory session registry, keyed by uploadId UUID. */
    private final ConcurrentHashMap<String, UploadSession> sessions = new ConcurrentHashMap<>();

    /**
     * Creates a new upload session for a large file.
     *
     * @param username         owner username from the authenticated JWT
     * @param originalFilename client-supplied filename (not yet sanitized)
     * @param totalSize        total file size in bytes; must not exceed {@code app.max-large-file-size-mb}
     * @param totalChunks      number of chunks the client will send; must be positive
     * @return the UUID {@code uploadId} that identifies this session
     * @throws IOException              if the temp directory cannot be created
     * @throws IllegalArgumentException if {@code totalSize} exceeds the configured limit
     *                                  or {@code totalChunks} is not positive
     */
    public String initSession(String username, String originalFilename,
                              long totalSize, int totalChunks) throws IOException {
        long maxBytes = appProperties.getMaxLargeFileSizeMb() * 1024L * 1024L;
        if (totalSize > maxBytes) {
            throw new IllegalArgumentException(
                    "File exceeds the " + appProperties.getMaxLargeFileSizeMb() + " MB limit");
        }
        if (totalChunks <= 0) {
            throw new IllegalArgumentException("totalChunks must be positive");
        }

        String uploadId = UUID.randomUUID().toString();
        Path tempDir = Paths.get(appProperties.getUploadDir(), "chunks", uploadId);
        Files.createDirectories(tempDir);

        sessions.put(uploadId, new UploadSession(
                uploadId, username, originalFilename, totalChunks, totalSize, tempDir));
        return uploadId;
    }

    /**
     * Stores a single chunk for an active upload session.
     *
     * @param uploadId   the session identifier returned by {@link #initSession}
     * @param chunkIndex zero-based index of this chunk; must be in {@code [0, totalChunks)}
     * @param chunkData  the raw chunk bytes as a multipart part
     * @param username   the requesting user; must match the session owner
     * @return a {@link ChunkUploadResponse} with the current received count and total
     * @throws IOException              if writing the chunk to disk fails
     * @throws IllegalArgumentException if {@code chunkIndex} is out of range
     * @throws AccessDeniedException    if {@code username} does not own the session
     * @throws RuntimeException         if no session exists for {@code uploadId}
     */
    public ChunkUploadResponse receiveChunk(String uploadId, int chunkIndex,
                                            MultipartFile chunkData, String username) throws IOException {
        UploadSession session = getSessionForUser(uploadId, username);

        if (chunkIndex < 0 || chunkIndex >= session.getTotalChunks()) {
            throw new IllegalArgumentException("Invalid chunk index: " + chunkIndex);
        }

        Path chunkPath = session.getTempDir().resolve(String.valueOf(chunkIndex));
        chunkData.transferTo(chunkPath);
        session.getReceivedChunks().add(chunkIndex);

        return new ChunkUploadResponse(uploadId,
                session.getReceivedChunks().size(), session.getTotalChunks());
    }

    /**
     * Assembles all received chunks, validates the result, and persists it as a finished file.
     *
     * <p>Chunks are concatenated in ascending index order (0 … N-1) into a UUID-named file
     * under {@code upload-dir}. The assembled file is then passed through
     * {@link FileSecurityService#validateAndGetMimeType(Path, String)} (extension block,
     * MIME detection, zip-bomb check). If validation fails the assembled file is deleted
     * before the exception propagates. The temp chunk directory is always cleaned up.
     *
     * @param uploadId the session identifier
     * @param username the requesting user; must match the session owner
     * @return a {@link FileMetadataDto} for the newly persisted file
     * @throws IOException              if assembly or disk I/O fails
     * @throws IllegalArgumentException if not all chunks have been received yet
     * @throws AccessDeniedException    if {@code username} does not own the session
     */
    public FileMetadataDto completeUpload(String uploadId, String username) throws IOException {
        UploadSession session = getSessionForUser(uploadId, username);

        if (!session.isComplete()) {
            throw new IllegalArgumentException("Not all chunks received: "
                    + session.getReceivedChunks().size() + "/" + session.getTotalChunks());
        }

        Path uploadDir = Paths.get(appProperties.getUploadDir());
        Files.createDirectories(uploadDir);
        String storedName = UUID.randomUUID().toString();
        Path assembledPath = uploadDir.resolve(storedName);

        // Concatenate chunks in order into a single file
        try (OutputStream out = Files.newOutputStream(assembledPath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            for (int i = 0; i < session.getTotalChunks(); i++) {
                Files.copy(session.getTempDir().resolve(String.valueOf(i)), out);
            }
        }

        String mimeType;
        try {
            mimeType = fileSecurityService.validateAndGetMimeType(
                    assembledPath, session.getOriginalFilename());
        } catch (Exception e) {
            // Security check failed — delete the assembled file before propagating
            Files.deleteIfExists(assembledPath);
            throw e;
        } finally {
            // Temp chunks are no longer needed regardless of outcome
            FileSystemUtils.deleteRecursively(session.getTempDir());
            sessions.remove(uploadId);
        }

        String sanitizedName = fileSecurityService.sanitizeFilename(session.getOriginalFilename());
        long actualSize = Files.size(assembledPath);

        return fileService.persistAssembledFile(
                storedName, assembledPath, sanitizedName, actualSize, mimeType, username);
    }

    /**
     * Cancels an in-progress upload and cleans up all temporary chunk files.
     *
     * @param uploadId the session identifier
     * @param username the requesting user; must match the session owner
     * @throws IOException           if deleting the temp directory fails
     * @throws AccessDeniedException if {@code username} does not own the session
     */
    public void abortUpload(String uploadId, String username) throws IOException {
        UploadSession session = getSessionForUser(uploadId, username);
        FileSystemUtils.deleteRecursively(session.getTempDir());
        sessions.remove(uploadId);
    }

    /**
     * Retrieves a session and enforces ownership.
     *
     * @param uploadId the session UUID
     * @param username the requesting user
     * @return the {@link UploadSession} if found and owned by {@code username}
     * @throws RuntimeException      if no session exists for the given ID
     * @throws AccessDeniedException if the session belongs to a different user
     */
    private UploadSession getSessionForUser(String uploadId, String username) {
        UploadSession session = sessions.get(uploadId);
        if (session == null) {
            throw new RuntimeException("Upload session not found: " + uploadId);
        }
        if (!session.getUsername().equals(username)) {
            throw new AccessDeniedException("Access denied");
        }
        return session;
    }
}
