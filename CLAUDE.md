# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
mvn wrapper:wrapper                                            # generate mvnw (one-time, needs Maven 3.7+)
./mvnw spring-boot:run                                        # dev server (H2 in-memory)
./mvnw test                                                    # all tests
./mvnw -Dtest=ClassName#methodName test                        # single test
./mvnw package                                                 # build JAR → target/
./mvnw spring-boot:run -Dspring-boot.run.profiles=prod        # PostgreSQL profile
```

H2 console at `http://localhost:8080/h2-console` (JDBC URL: `jdbc:h2:mem:fileuploaddb`) in dev.

## Architecture

**Package root:** `com.demo.fileupload`

**Auth flow:** `POST /api/auth/register` or `/login` → `AuthService` → JWT. Every subsequent API request carries `Authorization: Bearer <token>`. `JwtAuthenticationFilter` (`security/`) extends `OncePerRequestFilter`, validates the token, and sets `SecurityContextHolder`. `SecurityConfig` wires it before `UsernamePasswordAuthenticationFilter` with `STATELESS` session policy. The JWT signing key is derived by SHA-256-hashing `app.jwt-secret`, so any string works as the property value.

**File upload pipeline (small files ≤ `app.max-file-size-mb`):** `FileController.upload` → `FileService.upload` → `FileSecurityService.validateAndGetMimeType` (extension block → Apache Tika magic-number detection → zip-bomb ratio check) → `file.transferTo(UUID-named path)` → persist `FileMetadata`. The original filename is sanitized and stored only in the DB row; the on-disk name is always a UUID to prevent path traversal. Download reverses this via `UrlResource`.

**Chunked upload pipeline (large files > `app.max-file-size-mb`):** Frontend detects file size and calls `ChunkedUploadController` instead. Sequence: `POST /upload/init` creates an `UploadSession` in memory and a temp dir `{upload-dir}/chunks/{uploadId}/`; `POST /upload/{id}/chunk?chunkIndex=N` writes each chunk file; `POST /upload/{id}/complete` concatenates chunks in order, runs `FileSecurityService.validateAndGetMimeType(Path, String)` (Path-based overload that streams without loading into memory), then calls `FileService.persistAssembledFile` for DB persistence. On any failure the client calls `DELETE /upload/{id}` which deletes the temp dir.

**Access control:** Ownership check lives in `FileService.findWithAccess`. `ROLE_USER` sees only their own files. `ROLE_ADMIN` bypasses the ownership check and has exclusive access to `GET /api/files/all`. Each controller method derives `isAdmin` from `Authentication.getAuthorities()` and passes it down to the service.

**Account lockout:** `AuthService.login` increments `User.failedAttempts` on `BadCredentialsException`. At `app.max-login-attempts` the account is locked. `UserDetailsServiceImpl` propagates `accountLocked` to `UserDetails` so Spring rejects further attempts with `LockedException`.

**Frontend:** Static HTML served by `WebController`. No Thymeleaf expressions used — templates are pure HTML. `app.js` stores the JWT in `localStorage` and attaches `Authorization: Bearer …` to every `fetch` call. XSS in filenames is escaped via `escHtml()` before insertion into the DOM.

**Scan endpoint:** `GET /api/files/scan/{id}` is a stub in `FileController.rescan` — it re-fetches metadata and returns it. Hook in an async ClamAV call here and update `ScanStatus` accordingly.

## Tests

Three test classes in `src/test/java/com/demo/fileupload/`:

- `FileSecurityServiceTest` — pure unit test, no Spring context. Instantiates `FileSecurityService` directly. Covers blocked extensions, zip-bomb detection (creates a real zip programmatically), and filename sanitization. Fast.
- `AuthControllerTest` — `@SpringBootTest` + `@AutoConfigureMockMvc` + `@Transactional`. Creates users via `UserRepository` directly; no HTTP calls needed to set up state. Tests register/login/lockout flows.
- `FileControllerTest` — same setup, plus `@TestPropertySource(properties = "app.upload-dir=./target/test-uploads")` to redirect file I/O to the Maven clean target. Generates JWTs directly via `JwtService`. Tests upload/list/download/delete with ownership and admin scenarios.

`@Transactional` on `@SpringBootTest` (MOCK webEnvironment) rolls back DB changes after each test; files written to `./target/test-uploads` are removed by `mvn clean`.

Manual testing: `requests/api-requests.http` covers all 25 scenarios (IntelliJ HTTP Client / VS Code REST Client). Sample files in `samples/valid/` and `samples/invalid/` map directly to the expected 200 and 422 responses.

## Key configuration

See `application.properties` for all `app.*` properties (jwt-secret, upload-dir, max-file-size-mb, max-login-attempts, chunk-size-mb, max-large-file-size-mb). Prod overrides go in `application-prod.properties` (gitignored). Full property table in README.md.

## Tech stack

Spring Boot 3.2 · Spring Security 6 · Spring Data JPA · jjwt 0.12 · Apache Tika 2.9 · H2 (dev) / PostgreSQL (prod) · Lombok · Maven

## Documentation

This codebase is fully documented.

**Docs folder:** `docs/` in the project root contains four documents:

| File | Description |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System overview, Mermaid architecture diagram, component breakdown, data flow (upload, download, error paths), design decisions with rationale and trade-offs, common patterns, and known complexity areas |
| [`docs/FLOW.md`](docs/FLOW.md) | Step-by-step request and event lifecycle traces (registration, login, upload, download, delete), data models with all fields, state management (DB, filesystem, in-memory), async/background flows, error and exception propagation, and external data flows |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architectural decisions (14 documented decisions with rationale, trade-offs, alternatives, and code evidence), technology choices table, code organization patterns, constraint-driven decisions, and known technical debt items |
| [`docs/SECURITY.md`](docs/SECURITY.md) | JWT authentication model, file upload threat model and defences, missing controls with implementation guidance, access control, injection/XSS, brute-force lockout, transport security, secrets management, and production hardening checklist |
| [`docs/LARGE_FILE_UPLOADS.md`](docs/LARGE_FILE_UPLOADS.md) | Five approaches to large file uploads (client chunking, streaming, presigned URL, tus resumable, async queue) with rationale, comparison matrix, and full step-by-step implementation flow for the chunked upload path |

**Inline documentation conventions:**
- All Java source files use **Javadoc** (`/** ... */`) on every class, interface, enum constant, and public/private method.
- Inline `//` comments are added to non-trivial logic: complex conditionals, magic constants, algorithm steps, workarounds, and non-obvious behaviour.
- The JavaScript frontend (`app.js`) uses JSDoc-style block comments on all functions and `//` inline comments on non-obvious logic.

**Coverage:**
- `src/main/java/` — all 20 source files documented (config, controllers, DTOs, exceptions, models, repositories, security, services)
- `src/test/java/` — all 4 test classes documented with class-level Javadoc describing the test strategy and helper method Javadoc

*Documentation last generated/updated by the `documentation-writer` agent on 2026-04-18. All diagrams use Mermaid (sequenceDiagram and flowchart TD with subgraphs). All Java sources use Javadoc; JavaScript uses JSDoc.*
