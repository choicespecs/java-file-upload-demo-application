package com.demo.fileupload.config;

import com.demo.fileupload.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security filter-chain and authentication infrastructure configuration.
 *
 * <p>Key security decisions made here:
 * <ul>
 *   <li>CSRF protection is disabled for {@code /api/**} because the JavaScript frontend
 *       authenticates with stateless JWT bearer tokens and does not use cookies.</li>
 *   <li>The session policy is {@code STATELESS} — no {@code HttpSession} is ever created,
 *       which is correct for a JWT-only API.</li>
 *   <li>{@link JwtAuthenticationFilter} is inserted before
 *       {@link UsernamePasswordAuthenticationFilter} so that JWT-authenticated requests
 *       are processed before Spring's default form-login filter runs.</li>
 *   <li>H2 console iframes require {@code sameOrigin} frame-options; the default DENY
 *       would break the H2 web UI.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Defines the HTTP security rules and filter chain for the application.
     *
     * <p>Authorization rules (in evaluation order):
     * <ol>
     *   <li>{@code /api/auth/**} — publicly accessible (register, login)</li>
     *   <li>Static assets ({@code /css/**}, {@code /js/**}) — publicly accessible</li>
     *   <li>SPA pages ({@code /}, {@code /login}, {@code /register}) — publicly accessible</li>
     *   <li>H2 console ({@code /h2-console/**}) — publicly accessible in dev</li>
     *   <li>{@code /api/files/all} — requires {@code ROLE_ADMIN}</li>
     *   <li>All other requests — require any authenticated user</li>
     * </ol>
     *
     * @param http                   Spring's mutable HTTP security builder
     * @param jwtAuthFilter          the JWT extraction and validation filter
     * @param authenticationProvider the DAO provider wiring {@code UserDetailsService}
     *                               and {@code PasswordEncoder}
     * @return the built and immutable {@link SecurityFilterChain}
     * @throws Exception if the filter chain cannot be constructed
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                    JwtAuthenticationFilter jwtAuthFilter,
                                                    AuthenticationProvider authenticationProvider) throws Exception {
        http
            // CSRF disabled for the API; frontend uses JWT bearer tokens
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/css/**", "/js/**").permitAll()
                .requestMatchers("/", "/login", "/register").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/api/files/all").hasRole("ADMIN")
                .anyRequest().authenticated())
            // Allow H2 console to render in iframes; default DENY would break its UI
            .headers(headers -> headers.frameOptions(fo -> fo.sameOrigin()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configures a {@link DaoAuthenticationProvider} that looks up users from the database
     * and verifies passwords using BCrypt.
     *
     * @param userDetailsService Spring Data-backed user lookup service
     * @param passwordEncoder    BCrypt encoder used to verify stored password hashes
     * @return a fully configured {@link AuthenticationProvider}
     */
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                          PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    /**
     * Exposes the {@link AuthenticationManager} as a bean so that {@code AuthService}
     * can call it programmatically during the login flow.
     *
     * @param config Spring's auto-configured authentication configuration
     * @return the application-wide {@link AuthenticationManager}
     * @throws Exception if the manager cannot be resolved
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Provides a BCrypt password encoder bean used for hashing new passwords and
     * verifying login attempts. BCrypt is intentionally slow to mitigate brute-force attacks.
     *
     * @return a {@link BCryptPasswordEncoder} with the default work factor (10)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
