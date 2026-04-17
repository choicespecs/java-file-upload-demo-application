package com.demo.fileupload.controller;

import com.demo.fileupload.dto.FileDownloadResult;
import com.demo.fileupload.dto.FileMetadataDto;
import com.demo.fileupload.service.FileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

/**
 * REST controller for all file-related operations.
 *
 * <p>Every endpoint under {@code /api/files/**} requires a valid JWT
 * ({@code Authorization: Bearer <token>}). Access to individual files is further
 * scoped by ownership: a {@code ROLE_USER} caller may only act on their own files,
 * while a {@code ROLE_ADMIN} caller may act on any file. The admin check is resolved
 * here via {@link #isAdmin(Authentication)} and passed as a plain {@code boolean} to
 * service methods, keeping the service layer free of Spring Security dependencies.
 */
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {

    private final FileService fileService;

    /**
     * Accepts a multipart file upload, runs security validation, and persists metadata.
     *
     * <p>The file is rejected (HTTP 422) if it has a blocked extension, executable MIME type,
     * or is a zip-bomb. The on-disk filename is always a UUID; the original filename is
     * sanitized and stored only in the database.
     *
     * @param file the uploaded file from the {@code file} form field
     * @param auth the authenticated principal; {@code auth.getName()} is the owner username
     * @return HTTP 200 with {@link FileMetadataDto} for the saved file
     * @throws IOException if writing the file to disk fails
     */
    @PostMapping("/upload")
    public ResponseEntity<FileMetadataDto> upload(@RequestParam("file") MultipartFile file,
                                                   Authentication auth) throws IOException {
        return ResponseEntity.ok(fileService.upload(file, auth.getName()));
    }

    /**
     * Lists all files owned by the authenticated user.
     *
     * @param auth the authenticated principal
     * @return HTTP 200 with a (possibly empty) list of {@link FileMetadataDto}
     */
    @GetMapping
    public ResponseEntity<List<FileMetadataDto>> listMyFiles(Authentication auth) {
        return ResponseEntity.ok(fileService.listForUser(auth.getName()));
    }

    /**
     * Lists all files uploaded by all users. Restricted to {@code ROLE_ADMIN};
     * the authorization rule is enforced in {@link com.demo.fileupload.config.SecurityConfig}.
     *
     * @return HTTP 200 with a list of every {@link FileMetadataDto} in the system
     */
    @GetMapping("/all")
    public ResponseEntity<List<FileMetadataDto>> listAllFiles() {
        return ResponseEntity.ok(fileService.listAll());
    }

    /**
     * Downloads the file identified by {@code id}.
     *
     * <p>Sets {@code Content-Disposition: attachment} using the sanitized original filename
     * so the browser prompts a save dialog with the correct name. Falls back to
     * {@code application/octet-stream} if no MIME type was recorded.
     *
     * @param id   the database ID of the file
     * @param auth the authenticated principal
     * @return HTTP 200 with the file bytes and appropriate headers
     * @throws IOException if reading the file from disk fails
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller does not own the file and is not an admin
     */
    @GetMapping("/{id}")
    public ResponseEntity<org.springframework.core.io.Resource> download(@PathVariable Long id,
                                                                          Authentication auth) throws IOException {
        boolean isAdmin = isAdmin(auth);
        FileDownloadResult result = fileService.download(id, auth.getName(), isAdmin);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(result.originalFilename()).build());
        // Use stored MIME type if available; fall back to generic binary stream
        headers.setContentType(result.mimeType() != null
                ? MediaType.parseMediaType(result.mimeType())
                : MediaType.APPLICATION_OCTET_STREAM);

        return ResponseEntity.ok().headers(headers).body(result.resource());
    }

    /**
     * Returns metadata for the file identified by {@code id} without downloading the bytes.
     *
     * @param id   the database ID of the file
     * @param auth the authenticated principal
     * @return HTTP 200 with the {@link FileMetadataDto}
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller does not own the file and is not an admin
     */
    @GetMapping("/{id}/meta")
    public ResponseEntity<FileMetadataDto> getMeta(@PathVariable Long id, Authentication auth) {
        return ResponseEntity.ok(fileService.getMeta(id, auth.getName(), isAdmin(auth)));
    }

    /**
     * Deletes the file record and its backing bytes on disk.
     *
     * @param id   the database ID of the file to delete
     * @param auth the authenticated principal
     * @return HTTP 204 No Content on success
     * @throws IOException if deleting the file from disk fails
     * @throws org.springframework.security.access.AccessDeniedException
     *         (mapped to HTTP 403) if the caller does not own the file and is not an admin
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id, Authentication auth) throws IOException {
        fileService.delete(id, auth.getName(), isAdmin(auth));
        return ResponseEntity.noContent().build();
    }

    /**
     * Stub endpoint for triggering an antivirus rescan of an uploaded file.
     *
     * <p>Currently this re-fetches and returns the existing metadata unchanged.
     * To wire up real scanning: implement an async ClamAV call here (or in a
     * dedicated {@code ScanService}), update {@link com.demo.fileupload.model.ScanStatus}
     * on the entity, and return the updated metadata.
     *
     * @param id   the database ID of the file to rescan
     * @param auth the authenticated principal
     * @return HTTP 200 with the current (unmodified) {@link FileMetadataDto}
     */
    @GetMapping("/scan/{id}")
    public ResponseEntity<FileMetadataDto> rescan(@PathVariable Long id, Authentication auth) {
        // Placeholder: re-fetch metadata; hook up async ClamAV here and update ScanStatus
        return ResponseEntity.ok(fileService.getMeta(id, auth.getName(), isAdmin(auth)));
    }

    /**
     * Determines whether the authenticated principal holds {@code ROLE_ADMIN}.
     *
     * <p>This check is performed in the controller (rather than a service or AOP advice)
     * so that service methods receive a plain {@code boolean} and remain testable without
     * a live {@link org.springframework.security.core.context.SecurityContext}.
     *
     * @param auth the current authenticated principal
     * @return {@code true} if the principal's granted authorities include {@code ROLE_ADMIN}
     */
    private boolean isAdmin(Authentication auth) {
        return auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}
