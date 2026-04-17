package com.demo.fileupload.repository;

import com.demo.fileupload.model.FileMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

/**
 * Spring Data JPA repository for {@link FileMetadata} entities.
 *
 * <p>Inherits standard CRUD and pagination operations from {@link JpaRepository}.
 * The custom derived query method navigates the {@code owner} association to the
 * {@code users} table without requiring explicit JPQL.
 */
public interface FileMetadataRepository extends JpaRepository<FileMetadata, Long> {

    /**
     * Returns all file records owned by the specified username.
     *
     * <p>Spring Data derives the query {@code SELECT f FROM FileMetadata f WHERE f.owner.username = ?1},
     * which performs an implicit join to the {@code users} table.
     *
     * @param username the username of the owning {@link com.demo.fileupload.model.User}
     * @return a (possibly empty) list of all {@link FileMetadata} records for that user,
     *         in database insertion order
     */
    List<FileMetadata> findByOwnerUsername(String username);
}
