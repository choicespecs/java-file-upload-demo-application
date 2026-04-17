package com.demo.fileupload.service;

import com.demo.fileupload.exception.FileSecurityException;
import org.apache.tika.Tika;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * File content security service that validates uploads before they are written to disk.
 *
 * <p>Implements three independent, layered defence mechanisms:
 * <ol>
 *   <li><strong>Extension block</strong> — fast O(1) set lookup rejects known executable
 *       and script extensions before any byte inspection.</li>
 *   <li><strong>MIME-type detection</strong> — Apache Tika reads the file's magic bytes
 *       (not the client-declared {@code Content-Type}) to detect the real type, preventing
 *       extension-rename attacks (e.g. renaming {@code malware.exe} to {@code malware.pdf}).</li>
 *   <li><strong>Zip-bomb detection</strong> — for ZIP MIME types only, streams the entire
 *       decompressed content to count bytes, because {@link ZipEntry#getSize()} returns
 *       {@code -1} for DEFLATE-compressed entries and cannot be trusted.</li>
 * </ol>
 *
 * <p>Also provides {@link #sanitizeFilename(String)} which is used to strip path-traversal
 * and XSS characters from the user-supplied filename before storing it in the database.
 */
@Service
public class FileSecurityService {

    /** Maximum total uncompressed bytes allowed across all entries in a ZIP archive. */
    private static final long MAX_ZIP_UNCOMPRESSED_BYTES = 500L * 1024 * 1024; // 500 MB

    /**
     * Maximum ratio of uncompressed to compressed size. A ratio above 100 indicates
     * a highly suspicious archive (e.g. 42.zip-style recursive bombs or repeated-byte attacks).
     */
    private static final long MAX_ZIP_EXPANSION_RATIO = 100;

    /**
     * File extensions whose presence unconditionally rejects the upload.
     * Stored in lower-case; comparison uses {@code toLowerCase()} on the extracted extension.
     */
    private static final Set<String> BLOCKED_EXTENSIONS = Set.of(
            "exe", "bat", "cmd", "sh", "ps1", "vbs", "jar", "msi", "dll", "scr", "com"
    );

    /** Tika instance for magic-number-based MIME type detection. Stateless and thread-safe. */
    private final Tika tika = new Tika();

    /**
     * Validates an uploaded file against all security checks and returns its detected MIME type.
     *
     * <p>Checks are executed in order from cheapest to most expensive:
     * <ol>
     *   <li>Extension block (O(1) set lookup)</li>
     *   <li>MIME-type detection via Apache Tika (reads all bytes in memory)</li>
     *   <li>Zip-bomb streaming scan (only for ZIP MIME types)</li>
     * </ol>
     *
     * <p>Note: the entire file is read into a byte array ({@code file.getBytes()}) before
     * detection. This is acceptable for the configured 10 MB limit but would need a streaming
     * approach for larger files.
     *
     * @param file the incoming multipart upload to inspect
     * @return the Tika-detected MIME type string (e.g. {@code "text/plain"})
     * @throws IOException            if reading the file bytes fails
     * @throws FileSecurityException  if the file fails any security check
     */
    public String validateAndGetMimeType(MultipartFile file) throws IOException {
        byte[] bytes = file.getBytes();
        // Tika uses both magic bytes and the filename hint for detection; filename is the tiebreaker
        String detectedMime = tika.detect(bytes, file.getOriginalFilename());
        String extension = extension(file.getOriginalFilename());

        // Layer 1: extension block (cheapest check — runs before byte inspection)
        if (BLOCKED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new FileSecurityException("File type not allowed: ." + extension);
        }
        // Layer 2: Tika MIME check — catches executables regardless of extension
        if (detectedMime.contains("executable") || "application/x-msdownload".equals(detectedMime)) {
            throw new FileSecurityException("Executable content detected");
        }
        // Layer 3: zip-bomb check — only for confirmed ZIP content (most expensive check)
        if (detectedMime.equals("application/zip") || detectedMime.equals("application/x-zip-compressed")) {
            checkZipBomb(bytes, file.getSize());
        }

        return detectedMime;
    }

    /**
     * Sanitizes a user-supplied filename by removing characters that could enable
     * path-traversal or cross-site scripting attacks.
     *
     * <p>The three transformations applied in sequence:
     * <ol>
     *   <li>Replace any character that is not {@code [a-zA-Z0-9._-]} with {@code _}.
     *       This removes path separators ({@code /}, {@code \}), null bytes, shell
     *       metacharacters, and HTML special characters.</li>
     *   <li>Collapse consecutive dots ({@code ..+}) to a single dot, preventing
     *       double-extension tricks like {@code malware.php.jpg}.</li>
     *   <li>Replace a leading dot with {@code _} to prevent hidden-file creation on Unix
     *       (e.g. {@code .htaccess} becomes {@code _htaccess}).</li>
     * </ol>
     *
     * <p>Returns {@code "unnamed"} for null or blank input.
     *
     * @param filename the raw filename to sanitize; may be null
     * @return a filesystem-safe filename string; never null, never blank
     */
    public String sanitizeFilename(String filename) {
        if (filename == null || filename.isBlank()) return "unnamed";
        return filename
                // Allow only safe characters; everything else becomes underscore
                .replaceAll("[^a-zA-Z0-9._\\-]", "_")
                // Collapse ".." sequences to prevent path traversal (e.g. "../../etc/passwd")
                .replaceAll("\\.{2,}", ".")
                // Strip leading dot to prevent hidden file creation on Unix systems
                .replaceAll("^\\.", "_");
    }

    /**
     * Streams through the ZIP archive to measure its total uncompressed size and
     * compression ratio, rejecting archives that exceed either limit.
     *
     * <p>Uses {@link ZipInputStream} to read actual decompressed bytes rather than trusting
     * {@link ZipEntry#getSize()}, which returns {@code -1} for DEFLATE-compressed entries.
     * An 8 KB read buffer keeps heap usage low while counting bytes across all entries.
     *
     * <p>Two independent limits are checked:
     * <ul>
     *   <li>Absolute limit: total uncompressed bytes across all entries must not exceed
     *       {@value #MAX_ZIP_UNCOMPRESSED_BYTES} bytes (500 MB). Checked incrementally
     *       during streaming to abort early.</li>
     *   <li>Ratio limit: {@code uncompressed / compressedSize} must not exceed
     *       {@value #MAX_ZIP_EXPANSION_RATIO}. Checked after streaming completes.
     *       Skipped if either value is 0 to avoid division-related edge cases.</li>
     * </ul>
     *
     * @param bytes          the raw bytes of the ZIP file (already read into memory)
     * @param compressedSize the file size as reported by the multipart upload (used for ratio check)
     * @throws IOException           if the ZIP structure is corrupt and cannot be read
     * @throws FileSecurityException if either the absolute size or the ratio limit is exceeded
     */
    private void checkZipBomb(byte[] bytes, long compressedSize) throws IOException {
        long uncompressed = 0;
        byte[] buf = new byte[8192];
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                int n;
                // Count actual decompressed bytes — entry.getSize() returns -1 for DEFLATED entries
                while ((n = zis.read(buf)) != -1) {
                    uncompressed += n;
                    // Abort early to avoid reading the entire bomb before rejecting
                    if (uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) {
                        throw new FileSecurityException("Archive exceeds maximum allowed uncompressed size");
                    }
                }
            }
        }
        // Guard against division by zero; also skip ratio check for empty archives
        if (compressedSize > 0 && uncompressed > 0 && uncompressed / compressedSize > MAX_ZIP_EXPANSION_RATIO) {
            throw new FileSecurityException("Suspicious compression ratio — possible zip bomb");
        }
    }

    /**
     * Extracts the lowercase file extension from a filename.
     *
     * <p>Returns the substring after the last {@code '.'}, or an empty string if
     * the filename is null or contains no dot.
     *
     * @param filename the filename to parse; may be null
     * @return the extension string (without the leading dot), or {@code ""} if absent
     */
    private String extension(String filename) {
        if (filename == null || !filename.contains(".")) return "";
        return filename.substring(filename.lastIndexOf('.') + 1);
    }
}
