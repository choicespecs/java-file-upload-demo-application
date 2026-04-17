package com.demo.fileupload.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Servlet filter that extracts and validates a JWT from the {@code Authorization} header
 * and populates the Spring Security context for authenticated requests.
 *
 * <p>Extends {@link OncePerRequestFilter} to guarantee exactly-once execution per
 * request dispatch (including error dispatches), avoiding double-processing in
 * Spring MVC error forwarding scenarios.
 *
 * <p>The filter is <em>silent on failure</em>: if the header is absent, malformed, or
 * carries an invalid/expired token, the filter simply passes the request down the chain
 * without setting an authentication. Spring Security's downstream access-control rules
 * then produce a 401 or 403 response as appropriate.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * Attempts to authenticate the request from the {@code Authorization: Bearer <token>} header.
     *
     * <p>Processing steps:
     * <ol>
     *   <li>Check for a {@code Bearer } prefix; skip silently if absent.</li>
     *   <li>Extract the username claim from the token; skip silently on parse errors
     *       (expired, tampered, or malformed tokens).</li>
     *   <li>Skip if the security context already has an authentication set (e.g. from a
     *       previous filter or a nested dispatch).</li>
     *   <li>Load {@code UserDetails} from the database; validate the token against the
     *       loaded details (username match + not expired).</li>
     *   <li>If valid, create a {@link UsernamePasswordAuthenticationToken} with the user's
     *       authorities and set it in {@link SecurityContextHolder}.</li>
     * </ol>
     *
     * @param request  the incoming HTTP request
     * @param response the outgoing HTTP response
     * @param chain    the remaining filter chain
     * @throws ServletException if a servlet error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        // Pass through immediately if no Bearer token is present
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        // Strip the "Bearer " prefix (7 characters)
        String jwt = authHeader.substring(7);
        String username;
        try {
            username = jwtService.extractUsername(jwt);
        } catch (Exception e) {
            // Token is malformed, expired, or has an invalid signature — treat as unauthenticated
            chain.doFilter(request, response);
            return;
        }

        // Only authenticate if a username was extracted and the context is not already populated
        // (prevents re-authenticating on nested dispatches)
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (jwtService.isValid(jwt, userDetails)) {
                // Credentials are null because JWT is a self-contained token — no password needed
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                // Attach request details (remote address, session ID) for audit logging
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        chain.doFilter(request, response);
    }
}
