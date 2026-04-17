package com.demo.fileupload.security;

import com.demo.fileupload.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * Service for generating, parsing, and validating JSON Web Tokens (JWTs).
 *
 * <p>Uses jjwt 0.12 with HMAC-SHA256 signing. The signing key is derived by
 * SHA-256-hashing the raw {@code app.jwt-secret} string, which ensures the key
 * is always exactly 256 bits regardless of the input string length. This means
 * any ASCII string is a valid secret — no pre-encoding required.
 *
 * <p>Tokens contain a single {@code subject} claim set to the username. No roles
 * or other claims are embedded; roles are re-loaded from the database on each
 * request via {@link UserDetailsServiceImpl} to reflect any role changes immediately.
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final AppProperties appProperties;

    /**
     * Generates a signed JWT for the given user.
     *
     * <p>The token includes:
     * <ul>
     *   <li>{@code sub} — the username</li>
     *   <li>{@code iat} — current timestamp</li>
     *   <li>{@code exp} — current timestamp + {@code app.jwt-expiration-ms}</li>
     * </ul>
     *
     * @param userDetails the authenticated user; only the username is embedded in the token
     * @return a compact, URL-safe signed JWT string
     */
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + appProperties.getJwtExpirationMs()))
                .signWith(signingKey())
                .compact();
    }

    /**
     * Extracts the {@code subject} claim (username) from a token without validating expiry.
     *
     * <p>This method will throw if the token signature is invalid but not if the token
     * is expired — expiry is checked separately in {@link #isExpired(String)}.
     *
     * @param token a compact JWT string
     * @return the username embedded in the {@code sub} claim
     * @throws io.jsonwebtoken.JwtException if the token is malformed or the signature is invalid
     */
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Validates that the token belongs to the given user and has not expired.
     *
     * <p>Note: this method calls {@link #parseClaims(String)} twice (once via
     * {@link #extractUsername} and once via {@link #isExpired}), which is slightly
     * inefficient. Acceptable at demo scale.
     *
     * @param token       a compact JWT string
     * @param userDetails the user to validate the token against
     * @return {@code true} if the token subject matches the username and the token is not expired
     */
    public boolean isValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isExpired(token);
    }

    /**
     * Checks whether the token's {@code exp} claim is in the past.
     *
     * @param token a compact JWT string
     * @return {@code true} if the token has expired
     */
    private boolean isExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    /**
     * Parses and verifies the token signature, returning the claims payload.
     *
     * @param token a compact JWT string
     * @return the verified {@link Claims} payload
     * @throws io.jsonwebtoken.JwtException if parsing or signature verification fails
     */
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Derives the HMAC-SHA256 signing key by SHA-256-hashing the configured secret string.
     *
     * <p>HMAC-SHA256 requires a 256-bit key. Rather than requiring the operator to provide
     * a pre-encoded 32-byte value, we hash the raw secret string to produce exactly 32 bytes.
     * This makes any string (short, long, with special characters) a valid secret value.
     *
     * <p>This method is called on every token operation rather than cached; for high-throughput
     * production use, cache the result in a {@code @PostConstruct} field.
     *
     * @return a {@link SecretKey} suitable for HMAC-SHA256 signing
     * @throws IllegalStateException if SHA-256 is not available in the JVM (should never happen)
     */
    private SecretKey signingKey() {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(appProperties.getJwtSecret().getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the Java SE specification; this branch is unreachable
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
