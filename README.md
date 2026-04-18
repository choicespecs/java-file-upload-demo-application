# Java File Upload Demo

A secure file upload/download application built with Spring Boot 3.2, demonstrating REST API design, JWT authentication, and file security best practices.

## Features

- User registration and login with JWT-based authentication
- File upload with security scanning (MIME detection, zip-bomb protection, blocked extensions)
- **Chunked upload for large files** — files above 10 MB are automatically split into 5 MB chunks, uploaded sequentially with a live progress bar, and assembled server-side before validation
- File download with ownership enforcement
- Account lockout after repeated failed login attempts
- Admin role with access to all files
- Bootstrap 5 single-page frontend
- H2 in-memory database (dev) / PostgreSQL (prod)

## Prerequisites

- Java 17+
- Maven 3.8+ (or use the included wrapper once generated)

## Quick Start

```bash
# Generate the Maven wrapper scripts (one-time, requires Maven 3.7+ installed)
mvn wrapper:wrapper

# Run with H2 (dev mode)
./mvnw spring-boot:run
```

Open [http://localhost:8080](http://localhost:8080) — register an account, then upload files.

H2 console: [http://localhost:8080/h2-console](http://localhost:8080/h2-console)  
JDBC URL: `jdbc:h2:mem:fileuploaddb` · Username: `sa` · Password: _(blank)_

## Configuration

All app-specific settings are under the `app.*` prefix in `application.properties`:

| Property | Default | Description |
|---|---|---|
| `app.jwt-secret` | _(change me)_ | Secret for signing JWTs — any string works |
| `app.jwt-expiration-ms` | `86400000` | Token TTL (24 hours) |
| `app.upload-dir` | `./uploads` | Storage directory, created automatically |
| `app.max-file-size-mb` | `10` | Per-file size limit for the single-request upload path |
| `app.max-login-attempts` | `5` | Failed attempts before account lock |
| `app.chunk-size-mb` | `5` | Size of each chunk in the chunked upload path (frontend must match) |
| `app.max-large-file-size-mb` | `2048` | Maximum total file size allowed via chunked upload (2 GB) |

## Production (PostgreSQL)

1. Create `src/main/resources/application-prod.properties` (gitignored):

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/fileuploaddb
spring.datasource.username=${DB_USERNAME}
spring.datasource.password=${DB_PASSWORD}
spring.jpa.hibernate.ddl-auto=validate
app.jwt-secret=${JWT_SECRET}
app.upload-dir=/var/uploads/file-upload-demo
```

2. Run with the prod profile:

```bash
SPRING_PROFILES_ACTIVE=prod DB_USERNAME=... DB_PASSWORD=... JWT_SECRET=... ./mvnw spring-boot:run
```

## API Reference

All `/api/files/**` endpoints require `Authorization: Bearer <token>`.

### Auth

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register — returns JWT |
| `POST` | `/api/auth/login` | Login — returns JWT |

### Files

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/files/upload` | User | Upload a file (≤ `app.max-file-size-mb`) |
| `GET` | `/api/files` | User | List own files |
| `GET` | `/api/files/{id}` | Owner / Admin | Download file |
| `GET` | `/api/files/{id}/meta` | Owner / Admin | File metadata |
| `DELETE` | `/api/files/{id}` | Owner / Admin | Delete file |
| `GET` | `/api/files/all` | Admin only | List all files |
| `GET` | `/api/files/scan/{id}` | Owner / Admin | Trigger rescan (stub — returns current metadata) |

### Chunked Upload (large files)

For files larger than `app.max-file-size-mb` (default 10 MB), the frontend automatically uses this four-step sequence:

| Step | Method | Endpoint | Description |
|---|---|---|---|
| 1 | `POST` | `/api/files/upload/init` | Start session. Body: `{filename, totalSize, totalChunks}`. Returns `{uploadId}`. |
| 2 | `POST` | `/api/files/upload/{uploadId}/chunk?chunkIndex=N` | Send one chunk as multipart `chunk` field. Repeatable. |
| 3 | `POST` | `/api/files/upload/{uploadId}/complete` | Assemble chunks, run security validation, persist. Returns `FileMetadataDto`. |
| 4 | `DELETE` | `/api/files/upload/{uploadId}` | Abort and clean up temp files (called automatically on error). |

Chunk files are stored temporarily under `{upload-dir}/chunks/{uploadId}/` and deleted on completion or abort.

### Example (curl)

```bash
# Register
curl -s -X POST http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret123"}' | jq .

# Upload
TOKEN="<token from above>"
curl -s -X POST http://localhost:8080/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/file.pdf" | jq .

# List
curl -s http://localhost:8080/api/files \
  -H "Authorization: Bearer $TOKEN" | jq .
```

## Security

See [`SECURITY.md`](docs/SECURITY.md) for the full security guide, including:

- JWT authentication model, known gaps, and hardening steps
- File upload threat model and how each threat is addressed
- Missing defences (ClamAV, image re-encoding, dangerous MIME types) with implementation guidance
- Access control, injection/XSS, brute-force lockout, transport security, and secrets management
- Production hardening checklist

### File Upload Defences (summary)

Uploads go through `FileSecurityService` before being written to disk:

1. **Extension block** — rejects `.exe`, `.bat`, `.sh`, `.jar`, `.dll`, and similar executable types
2. **Magic-number detection** — Apache Tika reads file bytes (not the declared Content-Type) to detect the real MIME type
3. **Zip-bomb check** — ZIP files are rejected if the uncompressed size exceeds 500 MB or the compression ratio exceeds 100×
4. **Filename sanitization** — original filename is stripped of path-traversal characters; the on-disk name is always a random UUID

## Testing

### Running tests

```bash
./mvnw test                              # all tests
./mvnw -Dtest=FileSecurityServiceTest test   # unit tests only (no Spring context, fast)
./mvnw -Dtest=AuthControllerTest test        # auth integration tests
./mvnw -Dtest=FileControllerTest test        # file endpoint integration tests
```

Test uploads go to `./target/test-uploads` and are cleaned by `mvn clean`.

### Test coverage

| Test class | What it covers |
|---|---|
| `FileSecurityServiceTest` | MIME detection, blocked extensions (exe/sh/bat/dll), zip-bomb ratio check, filename sanitization |
| `AuthControllerTest` | Register success/duplicate/validation errors, login success/wrong-password/unknown-user/lockout, failed-attempt counter |
| `FileControllerTest` | Upload valid files, blocked extensions, no-auth, path traversal sanitization; list own vs others; download as owner/non-owner/admin; metadata access control; delete as owner/non-owner/admin |

### Sample files

```
samples/
├── valid/
│   ├── sample.txt        — plain text, accepted (small file → regular upload)
│   ├── sample.csv        — CSV, accepted
│   ├── sample.json       — JSON, accepted
│   ├── large-sample.bin  — 15 MB random binary (triggers chunked upload path)
│   └── large-sample.bin.txt — curl instructions for testing the chunked API directly
└── invalid/
    ├── blocked.exe  — rejected: File type not allowed: .exe (422)
    ├── blocked.sh   — rejected: File type not allowed: .sh  (422)
    └── README.txt   — documents other blocked types and zip-bomb behavior
```

Use `samples/valid/*` with curl or `requests/api-requests.http` to exercise happy-path uploads; use `samples/invalid/*` to confirm the 422 rejection responses.

To test chunked upload in the browser: start the dev server, log in, and select `large-sample.bin` — the file picker will show a progress bar as the 15 MB file is split into 3 × 5 MB chunks and assembled server-side.

### HTTP request file

`requests/api-requests.http` works with the **IntelliJ HTTP Client** or the **VS Code REST Client** extension. It covers all 25 request/response scenarios end-to-end and auto-captures the JWT token and file ID between requests — no manual copy-paste needed.

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Spring Boot 3.2, Spring Security 6 |
| Persistence | Spring Data JPA, H2 / PostgreSQL |
| Auth | jjwt 0.12 (HMAC-SHA256) |
| File detection | Apache Tika 2.9 |
| Frontend | Thymeleaf (template delivery), Bootstrap 5, Vanilla JS |
| Build | Maven |

## Project Structure

```
src/main/java/com/demo/fileupload/
├── config/          SecurityConfig, AppProperties
├── controller/      AuthController, FileController, ChunkedUploadController, WebController
├── dto/             Request/response objects, FileDownloadResult, Chunk*
├── exception/       FileSecurityException, GlobalExceptionHandler
├── model/           User, FileMetadata, Role, ScanStatus
├── repository/      UserRepository, FileMetadataRepository
├── security/        JwtService, JwtAuthenticationFilter, UserDetailsServiceImpl
└── service/         AuthService, FileService, FileSecurityService, ChunkedUploadService, UploadSession
```

## Architecture & Documentation

This application is a layered Spring Boot REST API with a stateless JWT authentication filter, a three-stage file security pipeline (extension blocking, Apache Tika MIME detection, zip-bomb streaming check), and role-based ownership access control. File bytes are stored under UUID-named paths to prevent path traversal; original filenames are sanitised and kept only in the database.

Four documentation files live in the `docs/` folder:

| File | Description |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System overview, ASCII architecture diagram, component breakdown, data flow, design decisions, common patterns, and known complexity areas |
| [`docs/FLOW.md`](docs/FLOW.md) | Step-by-step request lifecycle traces, data model field reference, state management (DB, filesystem), async/background flows, error propagation, and external data flows |
| [`docs/DESIGN.md`](docs/DESIGN.md) | 12 documented architectural decisions with rationale, trade-offs, and code evidence; technology choice table; code patterns; and known technical debt items |
| [`docs/SECURITY.md`](docs/SECURITY.md) | JWT auth model, file upload threat model, implemented defences, missing controls with implementation guidance, and production hardening checklist |
| [`docs/LARGE_FILE_UPLOADS.md`](docs/LARGE_FILE_UPLOADS.md) | Five approaches to large file uploads with trade-off analysis, comparison matrix, rationale for the chosen approach, and a full step-by-step implementation flow |

All Java source files are documented with Javadoc on every class and method. The JavaScript frontend (`app.js`) uses JSDoc block comments. Inline `//` comments explain non-obvious logic throughout.
