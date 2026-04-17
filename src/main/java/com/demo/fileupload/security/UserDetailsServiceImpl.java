package com.demo.fileupload.security;

import com.demo.fileupload.model.User;
import com.demo.fileupload.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Spring Security {@link UserDetailsService} implementation backed by {@link UserRepository}.
 *
 * <p>Called by {@link JwtAuthenticationFilter} on every authenticated request to refresh
 * user state from the database. This ensures that role changes and account lockouts are
 * reflected immediately without waiting for the JWT to expire.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads a {@link UserDetails} instance for the given username from the database.
     *
     * <p>Maps {@link User#isAccountLocked()} to {@link UserDetails#isAccountNonLocked()},
     * which Spring Security checks automatically. If the account is locked, Spring raises
     * {@link org.springframework.security.authentication.LockedException} before any
     * further processing occurs.
     *
     * <p>Only the role stored in the database is granted as an authority. Roles are
     * re-loaded from the DB on every request so that admin grants/revocations take effect
     * without token reissuance.
     *
     * @param username the username to look up
     * @return a populated {@link UserDetails} object including password hash, role, and lock state
     * @throws UsernameNotFoundException if no user with the given username exists in the database
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                // Map the single Role enum to a GrantedAuthority (e.g. "ROLE_USER")
                .authorities(List.of(new SimpleGrantedAuthority(user.getRole().name())))
                // Propagate DB lock state so Spring raises LockedException when true
                .accountLocked(user.isAccountLocked())
                .build();
    }
}
