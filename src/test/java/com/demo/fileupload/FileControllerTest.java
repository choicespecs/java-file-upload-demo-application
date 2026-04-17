package com.demo.fileupload;

import com.demo.fileupload.model.Role;
import com.demo.fileupload.model.User;
import com.demo.fileupload.repository.UserRepository;
import com.demo.fileupload.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the file management REST endpoints ({@code /api/files/**}).
 *
 * <p>Uses {@code @SpringBootTest} with the MOCK web environment and
 * {@code @AutoConfigureMockMvc} to exercise the full filter chain including JWT
 * authentication and Spring Security access control.
 *
 * <p>{@code @TestPropertySource} redirects file writes to {@code ./target/test-uploads},
 * which is cleaned by {@code mvn clean} so uploaded test files do not accumulate.
 *
 * <p>{@code @Transactional} rolls back all database changes after each test, but files
 * written to disk are NOT rolled back — they persist until {@code mvn clean}.
 *
 * <p>JWTs are generated directly via {@link JwtService} rather than by calling the login
 * endpoint, keeping test setup fast and decoupled from the auth flow.
 *
 * <p>Test categories:
 * <ul>
 *   <li>Upload — valid files, blocked extensions, unauthenticated, path traversal</li>
 *   <li>List — own files, isolation from other users' files, unauthenticated</li>
 *   <li>List all (admin) — admin access, user rejection</li>
 *   <li>Download — owner, non-owner (403), admin, non-existent ID</li>
 *   <li>Metadata — owner, non-owner (403)</li>
 *   <li>Delete — owner, non-owner (403), admin</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@TestPropertySource(properties = "app.upload-dir=./target/test-uploads")
class FileControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired JwtService jwtService;

    private String userToken;
    private String otherUserToken;
    private String adminToken;

    @BeforeEach
    void setup() {
        userToken  = tokenFor(saveUser("testuser",  Role.ROLE_USER));
        otherUserToken = tokenFor(saveUser("otheruser", Role.ROLE_USER));
        adminToken = tokenFor(saveUser("testadmin", Role.ROLE_ADMIN));
    }

    // ── Upload ────────────────────────────────────────────────────────────────

    @Test
    void upload_validTextFile_returns200WithMetadata() throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(textFile("hello.txt", "Hello, world!"))
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.originalFilename").value("hello.txt"))
                .andExpect(jsonPath("$.mimeType").value(containsString("text")))
                .andExpect(jsonPath("$.size").value(13))
                .andExpect(jsonPath("$.scanStatus").value("CLEAN"))
                .andExpect(jsonPath("$.ownerUsername").value("testuser"));
    }

    @Test
    void upload_csvFile_returns200() throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(new MockMultipartFile("file", "data.csv", "text/csv",
                        "name,age\nalice,30\nbob,25".getBytes()))
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.originalFilename").value("data.csv"));
    }

    @Test
    void upload_blockedExeExtension_returns422() throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(new MockMultipartFile("file", "virus.exe", "application/octet-stream",
                        "fake binary content".getBytes()))
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value(containsString(".exe")));
    }

    @Test
    void upload_blockedShellScript_returns422() throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(new MockMultipartFile("file", "deploy.sh", "text/x-sh",
                        "#!/bin/bash\nrm -rf /".getBytes()))
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value(containsString(".sh")));
    }

    @Test
    void upload_noAuth_returns401or403() throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(textFile("hello.txt", "content")))
                .andExpect(status().is(anyOf(is(401), is(403))));
    }

    @Test
    void upload_sanitizesFilename() throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(new MockMultipartFile("file", "../../etc/passwd", "text/plain",
                        "root:x:0:0".getBytes()))
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.originalFilename").value(not(containsString(".."))));
    }

    // ── List ──────────────────────────────────────────────────────────────────

    @Test
    void listMyFiles_empty_returns200WithEmptyArray() throws Exception {
        mockMvc.perform(get("/api/files")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void listMyFiles_afterUpload_returnsOwnFiles() throws Exception {
        uploadFile(userToken, "one.txt", "content one");
        uploadFile(userToken, "two.txt", "content two");

        mockMvc.perform(get("/api/files")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].ownerUsername", everyItem(is("testuser"))));
    }

    @Test
    void listMyFiles_doesNotReturnOtherUsersFiles() throws Exception {
        uploadFile(otherUserToken, "other.txt", "other content");

        mockMvc.perform(get("/api/files")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void listMyFiles_noAuth_returns401or403() throws Exception {
        mockMvc.perform(get("/api/files"))
                .andExpect(status().is(anyOf(is(401), is(403))));
    }

    // ── List all (admin) ──────────────────────────────────────────────────────

    @Test
    void listAll_asAdmin_returnsAllUsersFiles() throws Exception {
        uploadFile(userToken, "user-file.txt", "by user");
        uploadFile(otherUserToken, "other-file.txt", "by other");

        mockMvc.perform(get("/api/files/all")
                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))));
    }

    @Test
    void listAll_asUser_returns403() throws Exception {
        mockMvc.perform(get("/api/files/all")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isForbidden());
    }

    // ── Download ──────────────────────────────────────────────────────────────

    @Test
    void download_asOwner_returns200WithContent() throws Exception {
        Long id = uploadAndGetId(userToken, "download-me.txt", "file content here");

        mockMvc.perform(get("/api/files/" + id)
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        containsString("download-me.txt")))
                .andExpect(content().bytes("file content here".getBytes()));
    }

    @Test
    void download_asNonOwner_returns403() throws Exception {
        Long id = uploadAndGetId(userToken, "private.txt", "secret");

        mockMvc.perform(get("/api/files/" + id)
                .header(HttpHeaders.AUTHORIZATION, bearer(otherUserToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    void download_asAdmin_returns200() throws Exception {
        Long id = uploadAndGetId(userToken, "admin-can-see.txt", "sensitive data");

        mockMvc.perform(get("/api/files/" + id)
                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isOk());
    }

    @Test
    void download_nonExistentId_returns500() throws Exception {
        mockMvc.perform(get("/api/files/999999")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().is5xxServerError());
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    @Test
    void getMeta_asOwner_returnsMetadata() throws Exception {
        Long id = uploadAndGetId(userToken, "meta.txt", "content");

        mockMvc.perform(get("/api/files/" + id + "/meta")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.originalFilename").value("meta.txt"))
                .andExpect(jsonPath("$.scanStatus").value("CLEAN"))
                .andExpect(jsonPath("$.createdAt").isNotEmpty());
    }

    @Test
    void getMeta_asNonOwner_returns403() throws Exception {
        Long id = uploadAndGetId(userToken, "private.txt", "secret");

        mockMvc.perform(get("/api/files/" + id + "/meta")
                .header(HttpHeaders.AUTHORIZATION, bearer(otherUserToken)))
                .andExpect(status().isForbidden());
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    @Test
    void delete_asOwner_returns204AndRemovesFile() throws Exception {
        Long id = uploadAndGetId(userToken, "to-delete.txt", "bye");

        mockMvc.perform(delete("/api/files/" + id)
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isNoContent());

        // file no longer listed
        mockMvc.perform(get("/api/files")
                .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void delete_asNonOwner_returns403() throws Exception {
        Long id = uploadAndGetId(userToken, "keep.txt", "content");

        mockMvc.perform(delete("/api/files/" + id)
                .header(HttpHeaders.AUTHORIZATION, bearer(otherUserToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    void delete_asAdmin_returns204() throws Exception {
        Long id = uploadAndGetId(userToken, "admin-delete.txt", "content");

        mockMvc.perform(delete("/api/files/" + id)
                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isNoContent());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Creates and persists a {@link User} entity with a fixed BCrypt-hashed password of
     * {@code "password"}, suitable for token generation in tests.
     *
     * @param username desired username
     * @param role     role to assign
     * @return the saved {@link User} entity
     */
    private User saveUser(String username, Role role) {
        User u = new User();
        u.setUsername(username);
        u.setPassword(passwordEncoder.encode("password"));
        u.setRole(role);
        return userRepository.save(u);
    }

    /**
     * Generates a signed JWT for the given user by constructing a {@link UserDetails}
     * from the entity and calling {@link JwtService#generateToken}.
     *
     * <p>This bypasses the login endpoint so auth tests are decoupled from file tests.
     *
     * @param user the persisted user for whom to generate a token
     * @return a compact signed JWT string
     */
    private String tokenFor(User user) {
        UserDetails ud = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(List.of(new SimpleGrantedAuthority(user.getRole().name())))
                .build();
        return jwtService.generateToken(ud);
    }

    /**
     * Formats a token as an {@code Authorization} header value.
     *
     * @param token raw JWT string
     * @return the string {@code "Bearer <token>"}
     */
    private String bearer(String token) {
        return "Bearer " + token;
    }

    /**
     * Creates a {@link MockMultipartFile} with {@code text/plain} content type.
     *
     * @param name    the filename for the multipart part
     * @param content the file body as a plain string
     * @return a configured {@link MockMultipartFile}
     */
    private MockMultipartFile textFile(String name, String content) {
        return new MockMultipartFile("file", name, "text/plain", content.getBytes());
    }

    /**
     * Uploads a text file and discards the response. Used to set up state for
     * subsequent list/download/delete tests.
     *
     * @param token   bearer token for the uploading user
     * @param name    filename for the upload
     * @param content file body
     * @throws Exception if the MockMvc call fails
     */
    private void uploadFile(String token, String name, String content) throws Exception {
        mockMvc.perform(multipart("/api/files/upload")
                .file(textFile(name, content))
                .header(HttpHeaders.AUTHORIZATION, bearer(token)));
    }

    /**
     * Uploads a text file and parses the {@code id} field from the JSON response.
     *
     * <p><strong>Implementation note:</strong> The ID is extracted by string search rather
     * than JSON deserialization to avoid adding an extra test dependency. This relies on
     * {@code "id"} being the first key in the serialized {@link FileMetadataDto} — if field
     * ordering changes (e.g. via {@code @JsonPropertyOrder}), this helper would break.
     *
     * @param token   bearer token for the uploading user
     * @param name    filename for the upload
     * @param content file body
     * @return the database ID of the newly uploaded file
     * @throws Exception if the MockMvc call fails or the response cannot be parsed
     */
    private Long uploadAndGetId(String token, String name, String content) throws Exception {
        MvcResult result = mockMvc.perform(multipart("/api/files/upload")
                .file(textFile(name, content))
                .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        // Parse "id" from JSON by string search — see note in Javadoc above
        int start = body.indexOf("\"id\":") + 5;
        int end = body.indexOf(",", start);
        return Long.parseLong(body.substring(start, end).trim());
    }
}
