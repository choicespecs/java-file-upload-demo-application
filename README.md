# Java File Upload Demo

A secure file upload/download application built with Spring Boot 3.2, demonstrating REST API design, JWT authentication, and file security best practices.

## Features

- User registration and login with JWT-based authentication
- File upload with security scanning (MIME detection, zip-bomb protection, blocked extensions)
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
| `app.max-file-size-mb` | `10` | Per-file size limit |
| `app.max-login-attempts` | `5` | Failed attempts before account lock |

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
| `POST` | `/api/files/upload` | User | Upload a file |
| `GET` | `/api/files` | User | List own files |
| `GET` | `/api/files/{id}` | Owner / Admin | Download file |
| `GET` | `/api/files/{id}/meta` | Owner / Admin | File metadata |
| `DELETE` | `/api/files/{id}` | Owner / Admin | Delete file |
| `GET` | `/api/files/all` | Admin only | List all files |
| `GET` | `/api/files/scan/{id}` | Owner / Admin | Trigger rescan (stub — returns current metadata) |

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

## File Security

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
│   ├── sample.txt   — plain text, accepted
│   ├── sample.csv   — CSV, accepted
│   └── sample.json  — JSON, accepted
└── invalid/
    ├── blocked.exe  — rejected: File type not allowed: .exe (422)
    ├── blocked.sh   — rejected: File type not allowed: .sh  (422)
    └── README.txt   — documents other blocked types and zip-bomb behavior
```

Use `samples/valid/*` with curl or `requests/api-requests.http` to exercise happy-path uploads; use `samples/invalid/*` to confirm the 422 rejection responses.

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
├── controller/      AuthController, FileController, WebController
├── dto/             Request/response objects, FileDownloadResult
├── exception/       FileSecurityException, GlobalExceptionHandler
├── model/           User, FileMetadata, Role, ScanStatus
├── repository/      UserRepository, FileMetadataRepository
├── security/        JwtService, JwtAuthenticationFilter, UserDetailsServiceImpl
└── service/         AuthService, FileService, FileSecurityService
```

## Architecture & Documentation

This application is a layered Spring Boot REST API with a stateless JWT authentication filter, a three-stage file security pipeline (extension blocking, Apache Tika MIME detection, zip-bomb streaming check), and role-based ownership access control. File bytes are stored under UUID-named paths to prevent path traversal; original filenames are sanitised and kept only in the database.

For a full system description including an architecture diagram, component breakdown, detailed data flow, and documented design decisions, see [`ARCHITECTURE.md`](./ARCHITECTURE.md).

All Java source files are documented with Javadoc on every class and method. The JavaScript frontend (`app.js`) uses JSDoc block comments. Inline `//` comments explain non-obvious logic throughout.
