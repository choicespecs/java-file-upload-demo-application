package com.demo.fileupload.dto;

import org.springframework.core.io.Resource;

/**
 * Internal value type returned by {@link com.demo.fileupload.service.FileService#download}
 * to carry all data needed by {@link com.demo.fileupload.controller.FileController} to
 * build the HTTP download response.
 *
 * <p>This record decouples the service (which should not know about HTTP headers) from
 * the controller (which must set {@code Content-Disposition} and {@code Content-Type}).
 *
 * @param resource         a {@link Resource} backed by the file path on disk
 * @param originalFilename the sanitized, human-readable filename used in the
 *                         {@code Content-Disposition: attachment; filename="..."} header
 * @param mimeType         the Tika-detected MIME type string (e.g. {@code "text/plain"}),
 *                         or {@code null} if detection was not performed; the controller
 *                         falls back to {@code application/octet-stream} when null
 */
public record FileDownloadResult(Resource resource, String originalFilename, String mimeType) {}
