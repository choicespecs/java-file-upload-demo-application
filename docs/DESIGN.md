# Design Decisions — Java File Upload Demo

This document captures the significant architectural and implementation choices visible in the codebase. For each decision, it records what was chosen, the inferred rationale, the trade-offs accepted, and the evidence in the code. Where intent is ambiguous, all plausible interpretations are listed.

---

## 3.1 Architectural Decisions

---

### Decision 1: Stateless JWT authentication with no server-side sessions

**Decision:** Every API request carries a self-contained signed JWT in the `Authorization: Bearer` header. The server never creates an `HttpSession`.

**Context:** The application exposes a REST API consumed by a JavaScript frontend. Authentication state must survive page navigations and, in a multi-instance deployment, requests routed to different servers.

**Rationale:** Stateless tokens eliminate the need for a shared session store (Redis, sticky sessions) to support horizontal scaling. They are idiomatic for REST APIs consumed by SPAs. Spring Security makes the STATELESS session policy first-class via `SessionCreationPolicy.STATELESS`.

**Trade-offs:**
- JWTs cannot be revoked before their `exp` claim expires without additional infrastructure (a token blocklist). A stolen token is valid for the full TTL (24 hours default).
- The token is stored in `localStorage`, which is accessible to JavaScript — a stored-XSS vulnerability could exfiltrate it. `HttpOnly` cookies would be more secure but require CSRF protection.
- Roles are loaded from the database on each request rather than embedded in the token, so role changes are reflected immediately. This adds one DB query per request but is correct behavior.

**Alternatives considered:** The presence of `WebController`, Thymeleaf, and `thymeleaf-extras-springsecurity6` in `pom.xml` suggests server-side session-based authentication was the original or an alternative approach that was kept as dead code. No session-based login flow exists in the current code.

**Consequences:** Any future feature that requires server-side session state (e.g., multi-step wizards, server-sent events with authentication) must work around the STATELESS policy.

**Evidence:** `SecurityConfig.securityFilterChain` line `.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))`; `JwtAuthenticationFilter.java`; `JwtService.java`.

---

### Decision 2: SHA-256 hash of the raw secret string as the HMAC-SHA256 signing key

**Decision:** The signing key for HMAC-SHA256 JWTs is derived by SHA-256-hashing the raw value of `app.jwt-secret` rather than using it directly.

**Context:** HMAC-SHA256 requires a 256-bit (32-byte) key. The `app.jwt-secret` property is a human-readable string of arbitrary length. jjwt rejects keys that are too short for the algorithm.

**Rationale:** SHA-256 always produces exactly 32 bytes regardless of input length, so any string — short, long, with special characters — is a valid secret value without operator confusion or silent truncation/padding. This is an operator experience improvement: the README can say "any string works" and be correct.

**Trade-offs:**
- Slightly non-standard: most JWT implementations use the raw secret bytes (with base64url encoding) or a dedicated key derivation function. A developer unfamiliar with this codebase might be confused.
- The SHA-256 hash is computed on every token generation and validation operation. For a demo this is negligible; in a high-throughput service it should be cached in a `@PostConstruct` field.
- The default secret value (`"change-this-to-a-long-random-secret-in-production-environments"`) is committed in source. If deployed without changing it, tokens can be forged by anyone who reads the code.

**Evidence:** `JwtService.signingKey()` method; `AppProperties.jwtSecret` default value; comment in `JwtService`: "The JWT signing key is derived by SHA-256-hashing `app.jwt-secret`, so any string works as the property value."

---

### Decision 3: UUID-named files on disk, sanitized original filename stored only in the database

**Decision:** Uploaded files are written to disk under a `UUID.randomUUID().toString()` filename. The original filename is sanitized and stored in `file_metadata.original_filename` for display and `Content-Disposition` only. The on-disk `filename` (UUID) and `storage_path` are never sent to clients.

**Context:** File upload path traversal (`../../etc/cron.d/payload`) and stored-path disclosure are classic web application vulnerabilities. The filename the user provides cannot be trusted.

**Rationale:** Using a UUID as the filesystem name makes path traversal structurally impossible — the UUID contains no path separators and is independent of user input. Even if the sanitizer failed or was bypassed, the on-disk path would still be `<uploadDir>/<uuid>` with no user-controlled component. The sanitized original filename is preserved purely as human-readable metadata.

**Trade-offs:**
- If the database is lost, files on disk cannot be identified or attributed — they become anonymous UUIDs. Acceptable for a demo; production needs coordinated backup and restore procedures.
- Extension-based file type detection by the OS/file manager is lost (files have no extension on disk). This is intentional from a security standpoint.

**Consequences:** Any feature that needs the actual file (streaming, transcoding, AV scanning) must use `storagePath` from the database. The `FileMetadataDto` deliberately omits `storagePath` and `filename` (UUID) to prevent clients from learning the storage layout.

**Evidence:** `FileService.upload`: `String storedName = UUID.randomUUID().toString()` and `meta.setFilename(storedName)`, `meta.setStoragePath(target.toAbsolutePath().toString())`; `FileMetadataDto.java` field list; `FileService.toDto` — `storagePath` and `filename` are not copied to the DTO.

---

### Decision 4: Two-layer file security — extension block and MIME detection

**Decision:** File validation uses both an extension blocklist (`Set<String> BLOCKED_EXTENSIONS`) and Apache Tika magic-number MIME detection. Both checks must pass. Checks are ordered from cheapest to most expensive.

**Context:** Neither extension-only nor MIME-only filtering is sufficient alone. Extension-only can be defeated by renaming (`malware.exe` → `malware.pdf`). MIME-only could be defeated by obscure Tika edge cases or new file formats Tika doesn't recognize, and is more expensive.

**Rationale:** Defence in depth. The extension check handles the common case quickly (O(1) set lookup). Tika handles extension-rename attacks by reading magic bytes. Running them in sequence means blocked-extension files are rejected without the cost of Tika detection; Tika only runs on files that passed the extension check.

**Trade-offs:**
- Tika reads the entire file into a `byte[]` before detection (`file.getBytes()`). For the 10 MB file size limit this is acceptable, but a streaming approach would be needed for larger limits.
- The extension block is not comprehensive — `html`, `svg`, `php`, `xml`, and others are not currently blocked. See `docs/SECURITY.md` section 4.3 for the full list to add.

**Consequences:** Adding a new blocked type requires updating `BLOCKED_EXTENSIONS` and potentially adding a MIME-type check in `validateAndGetMimeType`. Both changes are localized to `FileSecurityService`.

**Evidence:** `FileSecurityService.validateAndGetMimeType` method; `BLOCKED_EXTENSIONS` constant; Tika detection and MIME check code.

---

### Decision 5: Zip-bomb detection by streaming actual decompressed bytes

**Decision:** ZIP files are validated by streaming all decompressed bytes through `ZipInputStream`, counting them, and rejecting archives that exceed 500 MB uncompressed or a 100× compression ratio.

**Context:** `ZipEntry.getSize()` returns -1 for DEFLATE-compressed entries — it is unreliable for detecting bombs. Trusting the compressed size or the ZIP central directory is insufficient.

**Rationale:** The only way to know the true uncompressed size is to actually decompress the data. `ZipInputStream` decompresses on the fly with minimal memory overhead (an 8 KB read buffer discards data after counting). Two independent limits (absolute size and ratio) catch different attack patterns: a large-but-plausible-ratio bomb hits the absolute limit; a small-but-highly-repetitive bomb hits the ratio limit.

**Trade-offs:**
- A maximally-allowed ZIP (10 MB compressed, <500 MB uncompressed) requires decompressing and discarding up to 500 MB of data. This consumes CPU and briefly holds 8 KB in the buffer. The early-exit on exceeding 500 MB limits worst-case work.
- This runs in the request thread, blocking the upload handler for the duration of the scan. An async design would improve concurrency but adds complexity.

**Possible rationale:** The 500 MB and 100× constants were likely chosen empirically. 500 MB is below typical server RAM limits for a demo. 100× is orders of magnitude above typical benign compression ratios (ZIP usually achieves 2–10×), leaving headroom for legitimately compressible files while catching bombed archives.

**Evidence:** `FileSecurityService.checkZipBomb`; constants `MAX_ZIP_UNCOMPRESSED_BYTES` and `MAX_ZIP_EXPANSION_RATIO`; comment "Count actual decompressed bytes — `entry.getSize()` returns -1 for DEFLATED entries."

---

### Decision 6: `isAdmin` boolean passed from controller to service

**Decision:** `FileController.isAdmin(Authentication)` extracts the admin flag and passes it as a primitive `boolean` to service methods. Service methods (`download`, `getMeta`, `delete`, `findWithAccess`) do not access `SecurityContextHolder`.

**Context:** The service layer needs to enforce ownership access control but should not be coupled to Spring Security's thread-local `SecurityContextHolder`.

**Rationale:** Services that access `SecurityContextHolder` directly are harder to unit test — tests must mock or populate the security context. Passing a plain `boolean` makes the service testable with `service.download(id, "username", true)` without any security infrastructure. The separation also makes the contract explicit: callers declare whether they are admins rather than the service inferring it from implicit context.

**Trade-offs:**
- Each controller method that calls a service method requiring the flag must call `isAdmin(auth)`. With three file endpoints plus `rescan`, this is repetitive.
- `@EnableMethodSecurity` is present in `SecurityConfig` but unused on service methods. `@PreAuthorize("hasRole('ADMIN')")` on service methods would be an alternative, but it was not used — possibly because it would require a security context in tests, or simply because the explicit-boolean approach was preferred.

**Alternative considered:** Method security via `@PreAuthorize`. Evidence: `@EnableMethodSecurity` is annotated on `SecurityConfig` but no `@PreAuthorize` annotations appear anywhere in the service or controller layers.

**Evidence:** `FileController.isAdmin`; `FileService.findWithAccess(Long id, String username, boolean isAdmin)`; `SecurityConfig` `@EnableMethodSecurity` annotation with no corresponding `@PreAuthorize` usage.

---

### Decision 7: `@Transactional` on service methods, not on repositories or controllers

**Decision:** `AuthService.register`, `AuthService.login`, `FileService.upload`, and `FileService.delete` are annotated with `@Transactional`. Controllers and repositories are not.

**Context:** Multiple database writes within one business operation (e.g., login increments `failedAttempts` and saves the user) must be atomic.

**Rationale:** Standard Spring layering. The service boundary is the natural unit of atomicity. Repository methods participate in an existing transaction if one is active, so explicit `@Transactional` on repositories would be redundant.

**Trade-offs:** `FileService.upload` mixes file I/O (`file.transferTo`) with a database write in a single `@Transactional` method. If the database `save` fails after the file has been written, the file is orphaned on disk. The `@Transactional` annotation rolls back the DB changes but cannot roll back the filesystem write. A correct implementation would clean up the orphaned file in a `catch` block (acknowledged in `FileService.upload` Javadoc as a known limitation).

**Evidence:** `@Transactional` on `AuthService.register`, `AuthService.login`, `FileService.upload`, `FileService.delete`; note in `FileService.upload` Javadoc: "if the database save fails after the file has been written to disk, the file will be orphaned."

---

### Decision 8: Centralized exception mapping via `@RestControllerAdvice`

**Decision:** All exception-to-HTTP-status mapping lives in `GlobalExceptionHandler`. Controllers throw typed domain exceptions (`FileSecurityException`, `BadCredentialsException`, `LockedException`, `AccessDeniedException`, `IllegalArgumentException`). The handler converts them to a uniform `{"error": "..."}` JSON body.

**Context:** Without central handling, each controller method would need try/catch blocks and `ResponseEntity` error-building logic, making every method verbose.

**Rationale:** Centralizing the mapping keeps controllers thin. The uniform `{"error": "..."}` shape means the frontend (`app.js`) always reads `response.error` regardless of which exception was thrown — no client-side status-code branching needed.

**Trade-offs:** The catch-all `RuntimeException` handler (HTTP 500) returns the raw exception message to the client. This is a known information disclosure risk called out in the handler's Javadoc and in `SECURITY.md`. In production it should return a generic message while logging the full exception server-side.

**Evidence:** `GlobalExceptionHandler.java`; `app.js` error handling always reads `err.error`.

---

### Decision 9: Frontend JWT storage in `localStorage`

**Decision:** The JWT, username, and role are stored in `localStorage` after a successful login or registration.

**Context:** The frontend is a vanilla JavaScript SPA running in a browser. It must survive page reloads and navigate between pages without re-authenticating.

**Rationale:** `localStorage` is the simplest mechanism for persisting client-side state across page navigations without server involvement. It is widely used for JWT storage in demo applications and tutorials.

**Trade-offs:** `localStorage` is accessible to any JavaScript running on the page — a stored-XSS vulnerability would allow script injection to read and exfiltrate the token. `HttpOnly` cookies are immune to JavaScript access and would be more secure. The application mitigates XSS risk via `escHtml()` and `escAttr()` in `app.js`, but `localStorage` JWT storage is still a known anti-pattern in production security guidance (e.g., OWASP JWT cheat sheet recommends `HttpOnly` cookies).

**Possible rationale:** `localStorage` was chosen for simplicity in a demo context. `HttpOnly` cookie storage requires CSRF protection, which adds implementation complexity. The trade-off is acceptable for a demonstration but should be addressed before production deployment.

**Evidence:** `login.html` and `register.html` inline scripts calling `localStorage.setItem('jwt', data.token)`; `app.js` reading `localStorage.getItem('jwt')`.

---

### Decision 10: `ScanStatus.CLEAN` set synchronously at upload time

**Decision:** After a file is successfully uploaded, its `scanStatus` is set to `CLEAN` immediately without performing any virus scan.

**Context:** The intended design includes async ClamAV antivirus scanning (`ScanStatus` enum, `scan/{id}` endpoint). The async integration is not yet implemented.

**Rationale:** Setting `CLEAN` synchronously allows the rest of the system (download, display, access control) to function without depending on incomplete scanning infrastructure. The `ScanStatus` enum, the `rescan` endpoint stub, and the Javadoc on both `FileMetadata` and `ScanStatus` document the intended future state clearly.

**Trade-offs:** Files are accessible for download before any real antivirus check. The application is not actually safe from malware delivery — Tika detects known executable formats but not novel malware embedded in documents or images.

**Consequences:** Implementing real scanning requires: changing the default to `PENDING`, implementing the async ClamAV call in `FileController.rescan` or a dedicated service, and optionally blocking downloads of `PENDING`/`INFECTED` files in `FileService.download`.

**Evidence:** `FileService.upload`: `meta.setScanStatus(ScanStatus.CLEAN)`; comment "Set CLEAN immediately; change to PENDING once async ClamAV scanning is integrated"; `FileController.rescan` Javadoc describes the stub.

---

### Decision 11: `findWithAccess` as the single ownership gate

**Decision:** All file operations that require ownership verification are routed through `FileService.findWithAccess(Long id, String username, boolean isAdmin)`. This is the only location in the codebase that checks whether a user owns a file.

**Context:** Four endpoints act on a specific file by ID (download, metadata, delete, rescan). Each must enforce the same ownership rule.

**Rationale:** Centralizing the ownership check prevents it from being accidentally omitted when adding a new file endpoint. The pattern is "load and authorize" — the check returns the `FileMetadata` entity if access is granted, so the caller always gets a verified entity reference.

**Trade-offs:** The method throws `RuntimeException` with a generic message when the file ID does not exist in the database, which maps to HTTP 500. A `ResourceNotFoundException` mapped to HTTP 404 would be more semantically correct and avoid revealing that "500 = not found" to clients.

**Evidence:** `FileService.findWithAccess`; called by `download`, `getMeta`, `delete`; comment: "This is the single authoritative access-control gate for all file operations."

---

### Decision 13: Chunked upload sessions stored in a `ConcurrentHashMap` (in-memory, not persisted)

**Decision:** `ChunkedUploadService` maintains active upload sessions in a `ConcurrentHashMap<String, UploadSession>` field. Sessions are never written to the database.

**Context:** Files larger than 10 MB cannot be sent as a single multipart request without risking memory pressure, client-side timeouts, and the existing 10 MB `FileService` size guard. A multi-step protocol is needed. Each step must correlate back to the same upload's temporary storage and metadata.

**Rationale:** An in-memory map is the simplest correct solution for a single-JVM deployment. It requires no schema migration, no new infrastructure dependency (Redis, database table), and no serialization of `Path` and `Instant` values. The demo runs as a single instance, so cross-node session sharing is not required.

**Trade-offs:**
- Sessions are lost if the JVM restarts. In-progress uploads must be restarted by the client.
- Not safe for multi-instance deployments behind a load balancer — consecutive chunk requests must hit the same JVM. A Redis-backed session store would solve this.
- No automatic expiry. `UploadSession.createdAt` is available as the data for TTL-based cleanup, but no `@Scheduled` task consumes it. Abandoned sessions accumulate until restart.

**Alternatives considered:**
- **Database-backed sessions:** A new `upload_sessions` table would survive restarts and support multiple nodes but adds schema complexity and a write on every chunk upload.
- **Redis:** Distributed in-memory store that survives node loss (with persistence); requires adding a Redis dependency and connection configuration.

**Consequences:** Any future multi-instance or high-availability deployment must replace the `ConcurrentHashMap` with a distributed store. The `ChunkedUploadService` interface should not change — only the backing store.

**Evidence:** `ChunkedUploadService.sessions` field; `UploadSession.createdAt`; absence of any `@Scheduled` annotation in the codebase.

---

### Decision 14: `validateAndGetMimeType` Path overload streams from disk, avoiding heap allocation for large files

**Decision:** A second overload `FileSecurityService.validateAndGetMimeType(Path filePath, String originalFilename)` was added for the chunked upload completion path. It uses `Tika.detect(File)` for magic-byte detection and `Files.newInputStream` for the zip-bomb check, rather than loading the entire file into a `byte[]`.

**Context:** The original `validateAndGetMimeType(MultipartFile)` overload calls `file.getBytes()`, which holds the full file in a heap `byte[]`. This is acceptable up to 10 MB (the single-request limit) but would allocate up to 2 GB on the heap for the maximum chunked upload size.

**Rationale:** The `Path`-based overload achieves the same security guarantees (same extension check, same Tika magic-byte database, same streaming zip-bomb decompression) without a heap `byte[]` allocation proportional to the file size. `Tika.detect(File)` internally reads only as many bytes as needed for magic-byte detection. The zip-bomb check was refactored to accept an `InputStream` argument instead of `byte[]` so both overloads can share the same streaming implementation.

**Trade-offs:**
- Two overloads that call Tika via slightly different APIs (`tika.detect(bytes, filename)` vs. `Tika.detect(file)`) could theoretically diverge in edge-case MIME decisions in future Tika versions. In practice they use the same detector registry.
- `checkZipBomb` now accepts an `InputStream` and a `compressedSize` long. Callers must supply the correct `compressedSize` — for the Path overload this is `Files.size(path)`.

**Evidence:** `FileSecurityService.validateAndGetMimeType(Path, String)` method; `checkZipBomb(InputStream, long)` signature; `ChunkedUploadService.completeUpload` calling the Path overload after assembly.

---

### Decision 12: Account lockout tracked in the `users` table with no automatic expiry

**Decision:** `failedAttempts` and `accountLocked` are columns on the `users` table. Lockout is permanent until manually reset (no `lockoutExpiry` timestamp).

**Context:** The brute-force mitigation needs to track failure state across requests in a stateless server.

**Rationale:** The simplest correct implementation for a demo. Storing lockout state in the same table as the user avoids an additional join or cache lookup on every login attempt.

**Trade-offs:** No automatic unlock means legitimate users who trigger the threshold must contact an administrator for manual DB intervention. No audit trail exists for when lockouts occurred. Production implementations typically add `lockoutExpiry` so accounts auto-unlock after a time window (e.g., 15 minutes).

**Possible rationale:** Manual unlock was likely chosen to keep the demo simple while still demonstrating the lockout concept. The known gaps are documented in `SECURITY.md` section 7.

**Evidence:** `User.accountLocked`, `User.failedAttempts` fields; `AuthService.login` lockout logic; no `lockoutExpiry` field or scheduled unlock job exists.

---

## 3.2 Technology Choices

| Technology | Version | Why chosen | Alternative displaced |
|---|---|---|---|
| **Spring Boot** | 3.2.5 | Opinionated, production-ready Java web framework with auto-configuration, embedded Tomcat, and first-class Spring Security integration | Raw Spring MVC / Jakarta EE |
| **Spring Security 6** | (via Boot 3.2) | Mature, well-tested security framework for Java; native JWT and filter-chain support | Rolling custom auth middleware |
| **jjwt** | 0.12.5 | The most widely-used Java JWT library; 0.12 is the current stable line with a modern fluent API; 0.9.x is EOL | Nimbus JOSE+JWT, Auth0 `java-jwt` |
| **Apache Tika** | 2.9.2 | Magic-number MIME detection from file bytes, not declared content type; recognizes hundreds of formats | `URLConnection.guessContentTypeFromStream` (less accurate), custom magic-byte maps |
| **Spring Data JPA + Hibernate** | (via Boot 3.2) | ORM with JPQL derived queries eliminates raw SQL for standard CRUD; parameterized queries prevent SQL injection by default | JDBC template, jOOQ |
| **H2** | 2.x | In-memory database for development — no external dependency, zero configuration, includes a web console | Testcontainers PostgreSQL (heavier, but more representative) |
| **PostgreSQL** | (runtime, any modern version) | Production-grade RDBMS; free, widely available, excellent JDBC support | MySQL/MariaDB (comparable choice) |
| **Lombok** | (via Boot 3.2) | Reduces boilerplate: `@Data` generates getters/setters/equals/hashCode; `@RequiredArgsConstructor` generates constructor injection | Manual boilerplate or IDE generation |
| **Thymeleaf** | (via Boot 3.2) | Serves static HTML templates; no Thymeleaf expressions are used — the templates are pure HTML | Serving static HTML directly from `src/main/resources/static/` |
| **Bootstrap 5** | 5.3.0 (CDN) | CSS utility framework for responsive layout and component styling without custom CSS | Tailwind CSS, Material Design |

---

## 3.3 Code Organization and Patterns

### Pattern: Package-by-layer structure

The project organizes code into `config/`, `controller/`, `dto/`, `exception/`, `model/`, `repository/`, `security/`, and `service/` packages under `com.demo.fileupload`. This is the classic Spring MVC layered architecture.

**Implication:** Cross-cutting concerns (security, config) have their own packages. Adding a new domain feature requires touching multiple packages. Package-by-feature (e.g., `auth/`, `files/`) would be an alternative for larger codebases.

**Evidence:** Package listing in `src/main/java/com/demo/fileupload/`.

---

### Pattern: Thin controllers, logic in services

Controllers (`AuthController`, `FileController`, `WebController`) contain no business logic. They validate input (via `@Valid`), delegate to services, and build HTTP responses. The only non-trivial controller logic is `FileController.isAdmin()` — present there intentionally to avoid coupling the service to `SecurityContextHolder`.

**Example:** `AuthController.register` is 3 lines: `ResponseEntity.ok(authService.register(request))`.

**Evidence:** All controller methods in `AuthController.java` and `FileController.java`.

---

### Pattern: DTO-first API surface — entities never returned from controllers

No JPA entity class (`User`, `FileMetadata`) is ever returned directly from a controller. The translation always goes through a DTO (`AuthResponse`, `FileMetadataDto`). This ensures internal storage details (hashed passwords, UUID filenames, storage paths) are never exposed.

**Example:** `FileService.toDto(FileMetadata)` maps the entity to `FileMetadataDto`, omitting `filename`, `storagePath`, and the full `User` association.

**Evidence:** `FileController` return types; `FileService.toDto`; `AuthService.register` and `AuthService.login` returning `AuthResponse`.

---

### Pattern: `@Valid` on request body parameters for early validation

Bean Validation annotations on request DTOs (`RegisterRequest`, `LoginRequest`) are enforced by `@Valid` in controller method signatures before service code runs. Violations produce a `MethodArgumentNotValidException` automatically mapped to HTTP 400.

**Example:** `RegisterRequest` has `@NotBlank @Size(min=3, max=50)` on `username` and `@NotBlank @Size(min=6, max=100)` on `password`. These constraints mirror the HTML form attributes in `register.html` but are authoritative server-side.

**Evidence:** `AuthController` method signatures; `RegisterRequest.java`; `LoginRequest.java`.

---

### Pattern: Consistent JSON error shape `{"error": "..."}`

All error responses follow a single-key map `{"error": "<message>"}`. This is enforced by `GlobalExceptionHandler` returning `Map.of("error", e.getMessage())`. Clients need only read `response.error` regardless of HTTP status code.

**Evidence:** All handler methods in `GlobalExceptionHandler.java`; `app.js` upload error handler reading `err.error`.

---

### Pattern: Enumerated status fields stored as strings

Both `Role` and `ScanStatus` enums use `@Enumerated(EnumType.STRING)`. String storage makes database rows human-readable and decoupled from the enum ordinal order (ordinal storage breaks when enum members are reordered).

**Evidence:** `User.role` annotated `@Enumerated(EnumType.STRING)`; `FileMetadata.scanStatus` annotated `@Enumerated(EnumType.STRING)`.

---

### Pattern: `@Transactional` on service write methods only

Read methods (`listForUser`, `listAll`, `getMeta`, `download`) are not marked `@Transactional`. Write methods (`upload`, `delete` in `FileService`; `register`, `login` in `AuthService`) are. This is the correct minimal-transaction scope — read-only calls do not need transaction overhead; write calls need atomicity.

**Note:** `toDto` accesses the lazy-loaded `owner` association. For write methods this works because the transaction is still open. For read methods (`listForUser`, `download`), the transaction is opened by the repository call and `toDto` is called within the same transactional unit of work because Spring Data JPA opens a transaction for `findByOwnerUsername` and `findById`. This is a subtle implicit transaction dependency.

**Evidence:** `@Transactional` annotations in `FileService` and `AuthService`.

---

### Pattern: Tests use `@Transactional` for isolation

Integration tests annotated with `@SpringBootTest` and `@Transactional` roll back all database changes after each test method. This means tests are isolated without explicit cleanup. Direct repository access (bypassing the REST API) is used for test setup to keep tests fast and decoupled.

**Evidence:** `AuthControllerTest` and `FileControllerTest` class-level `@Transactional`; `saveUser` helpers calling `userRepository.save` directly.

---

## 3.4 Constraint-Driven Decisions

### Performance constraints

**File size capped at 10 MB for single-request uploads** (`app.max-file-size-mb`): The 10 MB limit is mirrored in `spring.servlet.multipart.max-file-size=10MB`. Both must be kept in sync — the Spring limit is enforced before the controller runs; the `app.*` limit is the application-level check inside `FileService.upload`. The Tika detection reads the entire file into a `byte[]`, which means up to 10 MB of heap is used per concurrent upload. The limit was likely set to keep heap pressure predictable.

**Chunked upload size capped at 2048 MB** (`app.max-large-file-size-mb`): The chunked path applies a separate, much higher ceiling checked at session init time. `app.chunk-size-mb` (default 5 MB) is documented for frontend alignment — the server accepts any non-zero chunk size; this property exists so operators and the frontend can be configured consistently. Neither value is validated at startup; mismatches between server and client chunk size only cause problems if the client sends chunks larger than the server's multipart limits.

**Zip-bomb 8 KB buffer**: The 8 KB buffer in `checkZipBomb` keeps stack and heap overhead minimal while streaming. This is the standard Java I/O buffer size for balanced throughput vs. overhead.

**Signing key not cached**: `JwtService.signingKey()` recomputes the SHA-256 hash on every call. At demo scale this is insignificant. The Javadoc notes this as a known inefficiency and recommends caching at `@PostConstruct` for production.

---

### Compatibility constraints

**Java 17 target**: The `pom.xml` sets `<java.version>17</java.version>`. Java records (`FileDownloadResult`), sealed types, and `var` are available. The `FileDownloadResult` record uses Java 14+ record syntax. No compatibility shims or polyfills are needed.

**Spring Boot 3.2 parent**: Locks all Spring ecosystem dependencies (Spring Security 6, Hibernate 6, Jakarta EE 10 namespace) to tested, compatible versions. Upgrading Spring Boot upgrades the entire stack atomically.

---

### Operational constraints

**H2 dev, PostgreSQL prod profile split**: The dev environment uses `spring.jpa.hibernate.ddl-auto=create-drop` for auto-schema management. The prod profile sets `validate` to prevent Hibernate from modifying a production schema. This split requires that schema migrations are managed externally (currently manual; Flyway or Liquibase are the recommended additions).

**Upload directory created at runtime**: `Files.createDirectories(uploadDir)` in `FileService.upload` ensures the directory exists before writing. No startup check. If the application user lacks write permission, the first upload will fail with an `IOException` rather than a startup failure. A `@PostConstruct` check would surface this earlier.

**PostgreSQL connection via environment variables**: `application-prod.properties` references `${DB_USERNAME}`, `${DB_PASSWORD}`, `${JWT_SECRET}`. This is a 12-factor app pattern — all environment-specific values are injected at runtime, not baked into the artifact.

---

## 3.5 Known Trade-offs and Technical Debt

| Location | Issue | Severity | Recommended Fix |
|---|---|---|---|
| `GlobalExceptionHandler.handleRuntime` | Returns raw exception message to clients — may expose internal paths, class names, or SQL errors | High | Replace with a generic `"Internal server error"` message; log the full exception with a correlation ID server-side |
| `FileService.upload` | File written to disk before DB save; if save fails, the file is orphaned with no cleanup | Medium | Wrap `transferTo` + `save` in try/catch; delete the file in the catch block before re-throwing |
| `FileControllerTest.uploadAndGetId` | Parses the file ID from the JSON response string by string-searching rather than deserialization — brittle if Jackson field order changes | Low | Replace with `ObjectMapper.readValue` or a `JsonPath` expression |
| `JwtService.signingKey()` | SHA-256 hash recomputed on every token operation | Low | Cache `SecretKey` as a field initialized in `@PostConstruct` |
| `FileService.findWithAccess` | Throws `RuntimeException` (HTTP 500) when file ID does not exist — semantically should be HTTP 404 | Medium | Add a typed `ResourceNotFoundException` mapped to HTTP 404 in `GlobalExceptionHandler` |
| `AppProperties.jwtSecret` | Default value is a known string committed in source; if deployed unchanged, tokens can be forged | Critical | Add a `@PostConstruct` validator in `AppProperties` that throws if the value equals the default |
| `AuthService.login` — no `lastLogin` update | The `User.lastLogin` field exists but is never written by `AuthService.login` | Low | Add `user.setLastLogin(LocalDateTime.now())` in the success path |
| `scan/{id}` endpoint | Stub that returns metadata unchanged — no actual scan is performed | Medium (functional gap) | Implement async ClamAV integration; see `SECURITY.md` section 4.1 |
| No Flyway/Liquibase migrations | Schema relies on Hibernate auto-DDL in dev; no migration history for prod | Medium | Add Flyway to `pom.xml` with an initial migration script matching the current entity model |
| `@EnableMethodSecurity` unused | Annotation is present but no `@PreAuthorize` annotations exist in the codebase — dead configuration | Low | Either use method security for admin checks (replacing the `isAdmin` boolean pattern) or remove the annotation |
| No server-side error logging | Exceptions are mapped to HTTP responses but not logged | Medium | Add SLF4J `Logger` fields to services and log `WARN`/`ERROR` in exception handlers |
| No stale upload session cleanup | Abandoned in-progress chunked uploads accumulate in `ChunkedUploadService.sessions` and leave temp chunk files on disk indefinitely — no `@Scheduled` task expires old sessions | Medium | Add a `@Scheduled(fixedDelay = 900_000)` method that iterates sessions and calls `abortUpload(uploadId, session.getUsername())` for entries where `Instant.now().isAfter(session.getCreatedAt().plus(sessionTtl))`; make the TTL configurable via `app.*` |
| Chunked upload assembly is not transactional with disk cleanup | Between `FileService.persistAssembledFile` and the temp directory deletion, a JVM crash leaves both the assembled file and the temp directory on disk | Low | Move the cleanup into a `try/finally` block or use a `CompletableFuture` that guarantees cleanup regardless of persistence outcome |
| No per-chunk integrity verification | Chunks are written to disk and counted but their contents are not checksummed — a corrupted or truncated network transfer produces a silently-corrupted assembled file | Low | Accept an optional `chunkChecksum` (e.g., MD5 or CRC32) query parameter per chunk; verify it before writing; return HTTP 422 on mismatch so the client can retry |
