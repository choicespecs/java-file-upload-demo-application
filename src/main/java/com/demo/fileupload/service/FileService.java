package com.demo.fileupload.service;

import com.demo.fileupload.config.AppProperties;
import com.demo.fileupload.dto.FileDownloadResult;
import com.demo.fileupload.dto.FileMetadataDto;
import com.demo.fileupload.model.FileMetadata;
import com.demo.fileupload.model.ScanStatus;
import com.demo.fileupload.model.User;
import com.demo.fileupload.repository.FileMetadataRepository;
import com.demo.fileupload.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Core service for file upload, listing, download, and deletion.
 *
 * <p>Enforces per-file ownership access control through {@link #findWithAccess}, which is the
 * single gate for all file operations requiring identity verification. All public methods that
 * act on a specific file ID route through this helper.
 *
 * <p>On-disk storage uses UUID-named files under {@code app.upload-dir}. The mapping between
 * UUID (disk name) and original sanitized filename is maintained in {@link FileMetadata}.
 */
@Service
@RequiredArgsConstructor
public class FileService {

    private final FileMetadataRepository fileMetadataRepository;
    private final UserRepository userRepository;
    private final FileSecurityService fileSecurityService;
    private final AppProperties appProperties;

    /**
     * Validates and persists an uploaded file.
     *
     * <p>Processing steps:
     * <ol>
     *   <li>Enforce the configured file size limit.</li>
     *   <li>Run {@link FileSecurityService#validateAndGetMimeType} (extension block,
     *       MIME detection, zip-bomb check).</li>
     *   <li>Sanitize the original filename.</li>
     *   <li>Generate a UUID as the on-disk filename to prevent path traversal.</li>
     *   <li>Create the upload directory if absent, then write the file via
     *       {@link org.springframework.web.multipart.MultipartFile#transferTo}.</li>
     *   <li>Persist a {@link FileMetadata} record linked to the owner user.</li>
     * </ol>
     *
     * <p><strong>Note:</strong> if the database save fails after the file has been written to
     * disk, the file will be orphaned. A production implementation should clean up the
     * orphaned file in a {@code catch} block.
     *
     * @param file     the uploaded multipart file
     * @param username the username of the authenticated user who is uploading the file
     * @return a {@link FileMetadataDto} representing the saved record
     * @throws IOException              if writing the file to disk fails
     * @throws IllegalArgumentException (mapped to HTTP 400) if the file exceeds the size limit
     * @throws FileSecurityException    (mapped to HTTP 422) if the file fails a security check
     */
    @Transactional
    public FileMetadataDto upload(MultipartFile file, String username) throws IOException {
        // Convert MB limit to bytes for comparison with raw file size
        if (file.getSize() > appProperties.getMaxFileSizeMb() * 1024 * 1024) {
            throw new IllegalArgumentException("File exceeds the " + appProperties.getMaxFileSizeMb() + " MB limit");
        }

        String mimeType = fileSecurityService.validateAndGetMimeType(file);
        String sanitizedName = fileSecurityService.sanitizeFilename(file.getOriginalFilename());
        // UUID as on-disk filename eliminates path traversal and filename collision risks
        String storedName = UUID.randomUUID().toString();

        Path uploadDir = Paths.get(appProperties.getUploadDir());
        Files.createDirectories(uploadDir);
        Path target = uploadDir.resolve(storedName);
        file.transferTo(target);

        User owner = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        FileMetadata meta = new FileMetadata();
        meta.setFilename(storedName);
        meta.setOriginalFilename(sanitizedName);
        meta.setMimeType(mimeType);
        meta.setSize(file.getSize());
        // Store the absolute path so the upload-dir property can be changed without breaking existing records
        meta.setStoragePath(target.toAbsolutePath().toString());
        meta.setOwner(owner);
        // Set CLEAN immediately; change to PENDING once async ClamAV scanning is integrated
        meta.setScanStatus(ScanStatus.CLEAN);

        return toDto(fileMetadataRepository.save(meta));
    }

    /**
     * Persists metadata for a file that has already been written to disk by the chunked
     * upload pipeline.
     *
     * <p>This is the final step of the chunked upload flow: the chunks have been assembled,
     * security-validated, and written to {@code storedPath} before this method is called.
     * The method only creates the {@link FileMetadata} database record; it does not move or
     * copy any bytes.
     *
     * @param storedName        the UUID filename used on disk (returned from the assembly step)
     * @param storedPath        absolute path to the assembled file; stored in the DB record
     * @param sanitizedOriginal the sanitized original filename shown to users
     * @param size              actual size of the assembled file in bytes
     * @param mimeType          Tika-detected MIME type of the assembled file
     * @param username          the username of the file owner
     * @return a {@link FileMetadataDto} for the newly persisted record
     */
    @Transactional
    public FileMetadataDto persistAssembledFile(String storedName, Path storedPath,
                                                 String sanitizedOriginal, long size,
                                                 String mimeType, String username) {
        User owner = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        FileMetadata meta = new FileMetadata();
        meta.setFilename(storedName);
        meta.setOriginalFilename(sanitizedOriginal);
        meta.setMimeType(mimeType);
        meta.setSize(size);
        meta.setStoragePath(storedPath.toAbsolutePath().toString());
        meta.setOwner(owner);
        // Set CLEAN immediately; change to PENDING once async ClamAV scanning is integrated
        meta.setScanStatus(ScanStatus.CLEAN);

        return toDto(fileMetadataRepository.save(meta));
    }

    /**
     * Returns all files owned by the specified user.
     *
     * @param username the username whose files should be listed
     * @return a (possibly empty) list of {@link FileMetadataDto}, in database insertion order
     */
    public List<FileMetadataDto> listForUser(String username) {
        return fileMetadataRepository.findByOwnerUsername(username)
                .stream().map(this::toDto).collect(Collectors.toList());
    }

    /**
     * Returns all files in the system regardless of owner. Admin-only operation;
     * the caller must have already verified admin privileges.
     *
     * @return a list of {@link FileMetadataDto} for every file in the database
     */
    public List<FileMetadataDto> listAll() {
        return fileMetadataRepository.findAll()
                .stream().map(this::toDto).collect(Collectors.toList());
    }

    /**
     * Resolves the file bytes for download by constructing a {@link UrlResource} from
     * the stored absolute path.
     *
     * @param id      the database ID of the file to download
     * @param username the username of the requesting user (used for ownership check)
     * @param isAdmin  {@code true} if the caller holds {@code ROLE_ADMIN} (bypasses ownership)
     * @return a {@link FileDownloadResult} containing the {@link org.springframework.core.io.Resource},
     *         the original filename, and the MIME type
     * @throws IOException if the file cannot be resolved as a URL resource
     * @throws RuntimeException (mapped to HTTP 500) if the file record exists in the DB but
     *                          the backing file is missing from disk
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller does not own the file and is not an admin
     */
    public FileDownloadResult download(Long id, String username, boolean isAdmin) throws IOException {
        FileMetadata meta = findWithAccess(id, username, isAdmin);
        Resource resource = new UrlResource(Paths.get(meta.getStoragePath()).toUri());
        if (!resource.exists()) {
            // This can happen if the file was deleted outside the application
            throw new RuntimeException("File data not found on disk");
        }
        return new FileDownloadResult(resource, meta.getOriginalFilename(), meta.getMimeType());
    }

    /**
     * Returns metadata for a single file without providing the file bytes.
     *
     * @param id      the database ID of the file
     * @param username the username of the requesting user
     * @param isAdmin  {@code true} if the caller holds {@code ROLE_ADMIN}
     * @return the {@link FileMetadataDto} for the requested file
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller does not own the file and is not an admin
     */
    public FileMetadataDto getMeta(Long id, String username, boolean isAdmin) {
        return toDto(findWithAccess(id, username, isAdmin));
    }

    /**
     * Deletes the file from disk and removes its metadata record from the database.
     *
     * <p>Uses {@link Files#deleteIfExists} so that a missing file (already deleted externally)
     * does not cause an error — the DB record is still removed.
     *
     * @param id      the database ID of the file to delete
     * @param username the username of the requesting user
     * @param isAdmin  {@code true} if the caller holds {@code ROLE_ADMIN}
     * @throws IOException if deleting the file from disk fails
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller does not own the file and is not an admin
     */
    @Transactional
    public void delete(Long id, String username, boolean isAdmin) throws IOException {
        FileMetadata meta = findWithAccess(id, username, isAdmin);
        // deleteIfExists prevents failure when the file is already gone from disk
        Files.deleteIfExists(Paths.get(meta.getStoragePath()));
        fileMetadataRepository.delete(meta);
    }

    /**
     * Loads a {@link FileMetadata} entity by ID and enforces ownership access control.
     *
     * <p>This is the single authoritative access-control gate for all file operations.
     * Admin callers bypass the ownership check; regular users are rejected if the file's
     * owner does not match {@code username}.
     *
     * @param id       the database primary key of the file
     * @param username the username of the requesting user
     * @param isAdmin  {@code true} if the caller holds {@code ROLE_ADMIN}
     * @return the {@link FileMetadata} entity if the caller has access
     * @throws RuntimeException (mapped to HTTP 500) if no file with the given ID exists
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller is not the owner and not an admin
     */
    private FileMetadata findWithAccess(Long id, String username, boolean isAdmin) {
        FileMetadata meta = fileMetadataRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found: " + id));
        // Admins bypass the ownership check; users must own the file
        if (!isAdmin && !meta.getOwner().getUsername().equals(username)) {
            throw new AccessDeniedException("Access denied");
        }
        return meta;
    }

    /**
     * Maps a {@link FileMetadata} entity to a {@link FileMetadataDto}, omitting internal
     * storage fields ({@code filename} UUID and {@code storagePath}) that must not be
     * exposed to clients.
     *
     * @param m the entity to convert
     * @return a DTO containing only the fields safe for client consumption
     */
    private FileMetadataDto toDto(FileMetadata m) {
        FileMetadataDto dto = new FileMetadataDto();
        dto.setId(m.getId());
        dto.setOriginalFilename(m.getOriginalFilename());
        dto.setMimeType(m.getMimeType());
        dto.setSize(m.getSize());
        dto.setScanStatus(m.getScanStatus());
        // Accessing the lazy-loaded owner here; this method must be called within a transaction
        // or after the owner has already been loaded
        dto.setOwnerUsername(m.getOwner().getUsername());
        dto.setCreatedAt(m.getCreatedAt());
        return dto;
    }
}
