package com.demo.fileupload.service;

import com.demo.fileupload.config.AppProperties;
import com.demo.fileupload.dto.AuthResponse;
import com.demo.fileupload.dto.LoginRequest;
import com.demo.fileupload.dto.RegisterRequest;
import com.demo.fileupload.model.User;
import com.demo.fileupload.repository.UserRepository;
import com.demo.fileupload.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Business logic for user registration and authentication.
 *
 * <p>Registration BCrypt-hashes the password and immediately issues a JWT so the
 * client can begin making API calls without a separate login step.
 *
 * <p>Login delegates credential verification to {@link AuthenticationManager} (which uses
 * {@link com.demo.fileupload.security.UserDetailsServiceImpl} and BCrypt comparison internally).
 * Failed attempts are tracked on the {@link User} entity; the account is locked after
 * {@code app.max-login-attempts} consecutive failures.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AppProperties appProperties;

    /**
     * Creates a new user account and returns an immediately-valid JWT.
     *
     * <p>New accounts are always created with {@link com.demo.fileupload.model.Role#ROLE_USER}.
     * Admin accounts must be promoted directly in the database.
     *
     * @param request validated registration payload with username and plain-text password
     * @return an {@link AuthResponse} containing a freshly signed JWT, the username, and the role
     * @throws IllegalArgumentException (mapped to HTTP 400) if the username is already taken
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already taken");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        // Hash the password before persisting — the raw value is never stored
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        String token = jwtService.generateToken(buildUserDetails(user));
        return new AuthResponse(token, user.getUsername(), user.getRole().name());
    }

    /**
     * Authenticates a user and returns a JWT on success.
     *
     * <p>The method has a two-stage lock check to produce the correct behaviour:
     * <ol>
     *   <li>An entity-level lock check before calling {@code AuthenticationManager} lets
     *       {@code AuthService} throw {@link LockedException} directly with a controlled
     *       message, without going through Spring Security's internal machinery.</li>
     *   <li>If not locked, {@code AuthenticationManager.authenticate} is called. On
     *       {@link BadCredentialsException}, the failure counter is incremented in the same
     *       transaction (guaranteed by {@code @Transactional}) before re-throwing.</li>
     * </ol>
     *
     * <p>On success, {@code failedAttempts} is reset to 0 so that a single successful
     * login clears any partial failure history.
     *
     * @param request validated login payload with username and plain-text password
     * @return an {@link AuthResponse} containing a freshly signed JWT, the username, and the role
     * @throws BadCredentialsException (mapped to HTTP 401) if credentials are invalid or user not found
     * @throws LockedException         (mapped to HTTP 423) if the account has been locked
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        // Throw BadCredentialsException (not UsernameNotFoundException) for unknown users
        // to avoid revealing whether a username exists (username enumeration mitigation)
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        // Check lock state before invoking AuthenticationManager to short-circuit early
        if (user.isAccountLocked()) {
            throw new LockedException("Account is locked");
        }

        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            // Successful login — clear failure history
            user.setFailedAttempts(0);
            userRepository.save(user);
            // Use the UserDetails returned by AuthenticationManager (already loaded from DB)
            String token = jwtService.generateToken((UserDetails) auth.getPrincipal());
            return new AuthResponse(token, user.getUsername(), user.getRole().name());
        } catch (BadCredentialsException e) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            // Lock the account when the configured threshold is reached
            if (attempts >= appProperties.getMaxLoginAttempts()) {
                user.setAccountLocked(true);
            }
            // Persist the updated counter (and possible lock) before re-throwing;
            // @Transactional ensures the save commits even though an exception propagates
            userRepository.save(user);
            throw e;
        }
    }

    /**
     * Constructs a Spring Security {@link UserDetails} from a {@link User} entity.
     *
     * <p>Used after registration to generate a token without an extra database round-trip.
     * Does not set the {@code accountLocked} flag because newly registered users are
     * never locked.
     *
     * @param user the newly created and persisted user entity
     * @return a {@link UserDetails} containing username, BCrypt-hashed password, and role authority
     */
    private UserDetails buildUserDetails(User user) {
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getRole().name())
                .build();
    }
}
