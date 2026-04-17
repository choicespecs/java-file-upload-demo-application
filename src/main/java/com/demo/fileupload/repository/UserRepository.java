package com.demo.fileupload.repository;

import com.demo.fileupload.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link User} entities.
 *
 * <p>Inherits standard CRUD operations from {@link JpaRepository}.
 * The two custom derived query methods cover the primary lookup patterns in
 * {@link com.demo.fileupload.service.AuthService} and
 * {@link com.demo.fileupload.security.UserDetailsServiceImpl}.
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Looks up a user by their unique username.
     *
     * <p>Used in the login flow, JWT validation path ({@code UserDetailsServiceImpl}),
     * and file ownership resolution ({@code FileService}).
     *
     * @param username the unique username to search for
     * @return an {@link Optional} containing the {@link User} if found, or empty if not
     */
    Optional<User> findByUsername(String username);

    /**
     * Checks whether a username is already registered without loading the full entity.
     *
     * <p>Used by {@link com.demo.fileupload.service.AuthService#register} to validate
     * uniqueness before attempting to insert a new row. More efficient than
     * {@code findByUsername(...).isPresent()} because it translates to a
     * {@code SELECT EXISTS} query.
     *
     * @param username the username to check
     * @return {@code true} if a user with this username already exists
     */
    boolean existsByUsername(String username);
}
