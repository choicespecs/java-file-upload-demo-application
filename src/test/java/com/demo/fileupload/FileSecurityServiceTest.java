package com.demo.fileupload;

import com.demo.fileupload.exception.FileSecurityException;
import com.demo.fileupload.service.FileSecurityService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayOutputStream;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.*;

/**
 * Pure unit tests for {@link FileSecurityService}.
 *
 * <p>No Spring context is loaded — {@code FileSecurityService} is instantiated directly,
 * making these tests fast and independent of application wiring. Apache Tika is exercised
 * against real byte content rather than mocks to verify actual detection behaviour.
 *
 * <p>Test categories:
 * <ul>
 *   <li>MIME detection — accepted file types return a non-null MIME string</li>
 *   <li>Blocked extensions — rejected types throw {@link FileSecurityException}</li>
 *   <li>Zip-bomb detection — a real programmatically created ZIP with high ratio is rejected</li>
 *   <li>Filename sanitization — path traversal and special characters are stripped</li>
 * </ul>
 */
class FileSecurityServiceTest {

    private final FileSecurityService service = new FileSecurityService();

    // ── MIME detection ────────────────────────────────────────────────────────

    @Test
    void plainTextFile_returnsMimeType() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "readme.txt",
                "text/plain", "Hello world".getBytes());
        String mime = service.validateAndGetMimeType(file);
        assertThat(mime).contains("text");
    }

    @Test
    void csvFile_returnsTextMimeType() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "data.csv",
                "text/csv", "name,age\nalice,30".getBytes());
        String mime = service.validateAndGetMimeType(file);
        assertThat(mime).isNotNull();
    }

    @Test
    void jsonFile_returnsMimeType() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "data.json",
                "application/json", "{\"key\":\"value\"}".getBytes());
        String mime = service.validateAndGetMimeType(file);
        assertThat(mime).isNotNull();
    }

    // ── Blocked extensions ────────────────────────────────────────────────────

    @Test
    void exeExtension_throwsFileSecurityException() {
        MockMultipartFile file = new MockMultipartFile("file", "malware.exe",
                "application/octet-stream", "MZ fake binary".getBytes());
        assertThatThrownBy(() -> service.validateAndGetMimeType(file))
                .isInstanceOf(FileSecurityException.class)
                .hasMessageContaining(".exe");
    }

    @Test
    void shellScriptExtension_throwsFileSecurityException() {
        MockMultipartFile file = new MockMultipartFile("file", "script.sh",
                "text/x-sh", "#!/bin/bash\nrm -rf /".getBytes());
        assertThatThrownBy(() -> service.validateAndGetMimeType(file))
                .isInstanceOf(FileSecurityException.class)
                .hasMessageContaining(".sh");
    }

    @Test
    void batExtension_throwsFileSecurityException() {
        MockMultipartFile file = new MockMultipartFile("file", "run.bat",
                "text/plain", "@echo off\ndel /f /s /q C:\\".getBytes());
        assertThatThrownBy(() -> service.validateAndGetMimeType(file))
                .isInstanceOf(FileSecurityException.class)
                .hasMessageContaining(".bat");
    }

    @Test
    void dllExtension_throwsFileSecurityException() {
        MockMultipartFile file = new MockMultipartFile("file", "hook.dll",
                "application/octet-stream", new byte[]{0x4D, 0x5A, 0x00, 0x00});
        assertThatThrownBy(() -> service.validateAndGetMimeType(file))
                .isInstanceOf(FileSecurityException.class)
                .hasMessageContaining(".dll");
    }

    // ── Zip bomb ──────────────────────────────────────────────────────────────

    @Test
    void normalZip_passes() throws Exception {
        byte[] zip = createZip("hello.txt", "Hello, world!".getBytes(), 1);
        MockMultipartFile file = new MockMultipartFile("file", "archive.zip",
                "application/zip", zip);
        assertThatCode(() -> service.validateAndGetMimeType(file)).doesNotThrowAnyException();
    }

    @Test
    void zipBombByRatio_throwsFileSecurityException() throws Exception {
        // 200 entries × 10 KB of repeated 'A' — tiny compressed, huge uncompressed ratio
        byte[] repeated = new byte[10_000];
        java.util.Arrays.fill(repeated, (byte) 'A');
        byte[] zip = createZip("bomb.txt", repeated, 200);

        MockMultipartFile file = new MockMultipartFile("file", "bomb.zip",
                "application/zip", zip);
        assertThatThrownBy(() -> service.validateAndGetMimeType(file))
                .isInstanceOf(FileSecurityException.class)
                .hasMessageContaining("compression ratio");
    }

    // ── Filename sanitization ─────────────────────────────────────────────────

    @Test
    void sanitize_removesPathTraversal() {
        assertThat(service.sanitizeFilename("../../etc/passwd")).doesNotContain("..");
    }

    @Test
    void sanitize_removesSpecialChars() {
        assertThat(service.sanitizeFilename("<script>alert(1)</script>.txt"))
                .doesNotContain("<").doesNotContain(">");
    }

    @Test
    void sanitize_handlesLeadingDot() {
        assertThat(service.sanitizeFilename(".htaccess")).doesNotStartWith(".");
    }

    @Test
    void sanitize_handlesNull() {
        assertThat(service.sanitizeFilename(null)).isEqualTo("unnamed");
    }

    @Test
    void sanitize_handlesBlank() {
        assertThat(service.sanitizeFilename("   ")).isEqualTo("unnamed");
    }

    @Test
    void sanitize_preservesValidFilename() {
        assertThat(service.sanitizeFilename("report-2024_final.pdf"))
                .isEqualTo("report-2024_final.pdf");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Creates a valid ZIP archive with {@code entryCount} entries, each containing
     * {@code content} bytes, compressed at maximum level.
     *
     * <p>Using {@link Deflater#BEST_COMPRESSION} maximises the compression ratio, which
     * allows the zip-bomb test to trigger the ratio limit with fewer entries.
     * Entries are named {@code 0_<entryName>}, {@code 1_<entryName>}, etc. to avoid
     * duplicate-entry warnings from some ZIP implementations.
     *
     * @param entryName  base name appended to each entry's index prefix
     * @param content    raw bytes written into every entry
     * @param entryCount number of entries to create
     * @return a byte array containing the complete ZIP archive
     * @throws Exception if ZIP construction fails
     */
    private byte[] createZip(String entryName, byte[] content, int entryCount) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bos)) {
            zos.setLevel(Deflater.BEST_COMPRESSION);
            for (int i = 0; i < entryCount; i++) {
                zos.putNextEntry(new ZipEntry(i + "_" + entryName));
                zos.write(content);
                zos.closeEntry();
            }
        }
        return bos.toByteArray();
    }
}
