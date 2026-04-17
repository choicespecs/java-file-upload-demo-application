package com.demo.fileupload;

import com.demo.fileupload.model.Role;
import com.demo.fileupload.model.User;
import com.demo.fileupload.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the authentication REST endpoints ({@code /api/auth/**}).
 *
 * <p>Uses {@code @SpringBootTest} with the default MOCK web environment and
 * {@code @AutoConfigureMockMvc} so that requests go through the full Spring Security
 * filter chain without starting a real HTTP server.
 *
 * <p>{@code @Transactional} ensures every test method runs inside a transaction that
 * is rolled back on completion, so tests are isolated and do not leave data behind.
 * Users are created directly via {@link UserRepository} rather than through HTTP calls
 * to keep test setup fast and independent of the register endpoint.
 *
 * <p>Test categories:
 * <ul>
 *   <li>Register — success, duplicate username, validation constraint violations</li>
 *   <li>Login — success, wrong password, unknown user, failed-attempt counting, lockout</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    // ── Register ─────────────────────────────────────────────────────────────

    @Test
    void register_success_returns200WithTokenAndRole() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("alice", "password123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"));
    }

    @Test
    void register_duplicateUsername_returns400() throws Exception {
        saveUser("bob", "password", Role.ROLE_USER);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("bob", "newpassword")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Username already taken"));
    }

    @Test
    void register_usernameTooShort_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("ab", "password123")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_passwordTooShort_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("charlie", "abc")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_missingFields_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @Test
    void login_success_returns200WithToken() throws Exception {
        saveUser("dave", "secret123", Role.ROLE_USER);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("dave", "secret123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.username").value("dave"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"));
    }

    @Test
    void login_adminUser_returnsAdminRole() throws Exception {
        saveUser("superadmin", "adminpass", Role.ROLE_ADMIN);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("superadmin", "adminpass")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ROLE_ADMIN"));
    }

    @Test
    void login_wrongPassword_returns401() throws Exception {
        saveUser("eve", "correctpass", Role.ROLE_USER);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("eve", "wrongpass")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid credentials"));
    }

    @Test
    void login_unknownUser_returns401() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("nobody", "password")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid credentials"));
    }

    @Test
    void login_repeatedFailures_incrementsAttempts() throws Exception {
        saveUser("frank", "realpass", Role.ROLE_USER);

        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json("frank", "wrongpass")))
                    .andExpect(status().isUnauthorized());
        }

        User frank = userRepository.findByUsername("frank").orElseThrow();
        assert frank.getFailedAttempts() == 3;
        assert !frank.isAccountLocked();
    }

    @Test
    void login_lockedAccount_returns423() throws Exception {
        User locked = saveUser("grace", "pass", Role.ROLE_USER);
        locked.setAccountLocked(true);
        userRepository.save(locked);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json("grace", "pass")))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.error").value(containsString("locked")));
    }

    @Test
    void login_fiveFailures_locksAccount() throws Exception {
        saveUser("heidi", "realpass", Role.ROLE_USER);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json("heidi", "wrongpass")));
        }

        User heidi = userRepository.findByUsername("heidi").orElseThrow();
        assert heidi.isAccountLocked();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Creates and persists a {@link User} entity with a BCrypt-hashed password.
     *
     * @param username desired username
     * @param password plain-text password (will be hashed before storage)
     * @param role     role to assign
     * @return the saved {@link User} entity with its generated ID
     */
    private User saveUser(String username, String password, Role role) {
        User u = new User();
        u.setUsername(username);
        u.setPassword(passwordEncoder.encode(password));
        u.setRole(role);
        return userRepository.save(u);
    }

    /**
     * Serializes a username/password pair to a JSON string for use as a request body.
     *
     * @param username the username value
     * @param password the password value
     * @return a JSON string such as {@code {"username":"alice","password":"secret"}}
     * @throws Exception if Jackson serialization fails
     */
    private String json(String username, String password) throws Exception {
        return mapper.writeValueAsString(Map.of("username", username, "password", password));
    }
}
