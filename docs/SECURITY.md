# Security Guide

This document covers the security model of the Java File Upload Demo, explains every control that is already in place, identifies the known gaps that exist because this is a demo, and gives concrete guidance on hardening each area for production.

---

## Table of Contents

1. [Authentication and session security](#1-authentication-and-session-security)
2. [File upload threat model](#2-file-upload-threat-model)
3. [File upload defences — what is implemented](#3-file-upload-defences--what-is-implemented)
4. [File upload defences — what is missing and how to add it](#4-file-upload-defences--what-is-missing-and-how-to-add-it)
5. [Access control](#5-access-control)
6. [Injection and XSS](#6-injection-and-xss)
7. [Account brute-force and lockout](#7-account-brute-force-and-lockout)
8. [Transport security](#8-transport-security)
9. [Secrets management](#9-secrets-management)
10. [Dependency and supply-chain hygiene](#10-dependency-and-supply-chain-hygiene)
11. [Production hardening checklist](#11-production-hardening-checklist)

---

## 1. Authentication and session security

### What is implemented

- **Stateless JWT** — the server never creates an `HttpSession`. Every request must carry a valid `Authorization: Bearer <token>` header. `SecurityConfig` enforces `SessionCreationPolicy.STATELESS`.
- **HMAC-SHA256 signing** — `JwtService` derives a 256-bit key by SHA-256-hashing `app.jwt-secret`. The token cannot be forged without the secret.
- **BCrypt password hashing** — `SecurityConfig` wires `BCryptPasswordEncoder` (work factor 10). Stored hashes cannot be reversed if the database is leaked.
- **JWT expiry** — tokens expire after `app.jwt-expiration-ms` (default: 24 hours). `JwtService.isTokenExpired` checks the `exp` claim on every request.

### Known gaps

| Gap | Risk | Fix |
|---|---|---|
| JWT stored in `localStorage` | Accessible to any JavaScript on the page; a stored-XSS vulnerability could exfiltrate it | Use `HttpOnly` cookies instead; pair with `SameSite=Strict` and a per-request CSRF token |
| No token revocation | A stolen or compromised token is valid until it expires | Maintain a server-side revocation list (Redis set of revoked JTIs); check it in `JwtAuthenticationFilter` |
| No token refresh flow | Users with a valid token that is about to expire have no way to get a new one without re-logging in | Issue short-lived access tokens (15 min) and a longer-lived refresh token stored in an `HttpOnly` cookie |
| `app.jwt-secret` defaults to a placeholder | If the default is deployed as-is, tokens can be forged by anyone who reads the source | Require the secret at startup: add a `@PostConstruct` check in `AppProperties` that throws if the value equals the default |

### Guidance

**Minimum secret entropy.** The SHA-256 hashing step means any non-empty string produces a 256-bit key, but a guessable secret is still dangerous. Use at least 32 random characters from a CSPRNG:

```bash
openssl rand -base64 32
```

Set the result as `JWT_SECRET` in your environment and reference it in `application-prod.properties`:

```properties
app.jwt-secret=${JWT_SECRET}
```

---

## 2. File upload threat model

File upload is one of the highest-risk features in a web application. The threats addressed by this codebase fall into four categories:

| Threat | Description | Primary defence in this app |
|---|---|---|
| **Malware delivery** | Attacker uploads an executable file that another user or admin downloads and runs | Extension block + Tika MIME detection |
| **Path traversal** | Filename like `../../etc/cron.d/payload` overwrites a system file | UUID on-disk name + filename sanitization |
| **Zip bomb** | Highly compressed archive that expands to gigabytes and exhausts disk/memory | Streaming decompressed-byte counter with absolute and ratio limits |
| **Stored XSS via filename** | Filename containing `<script>` tags rendered into the DOM | `escHtml()` / `escAttr()` in `app.js`; sanitization in `FileSecurityService` |
| **SSRF via file content** | SVG or HTML file containing external references fetched by a server-side renderer | No server-side rendering of file content — files are served as raw bytes |
| **Content-type spoofing** | Attacker renames `malware.exe` to `photo.jpg` | Apache Tika reads magic bytes, ignoring the declared extension and `Content-Type` header |
| **Polyglot files** | File is simultaneously valid as two formats (e.g. PDF+ZIP) | Tika detects the dominant format; blocked MIME check rejects executable content |
| **Disk exhaustion** | Many large legitimate uploads fill the disk | `app.max-file-size-mb` cap + Spring's `spring.servlet.multipart.max-file-size` |

---

## 3. File upload defences — what is implemented

All validation lives in `FileSecurityService` (`src/main/java/com/demo/fileupload/service/FileSecurityService.java`).

### Layer 1 — Extension block (fast path)

```java
private static final Set<String> BLOCKED_EXTENSIONS = Set.of(
    "exe", "bat", "cmd", "sh", "ps1", "vbs", "jar", "msi", "dll", "scr", "com"
);
```

- Checked first because it is O(1).
- Comparison is case-insensitive (`toLowerCase()`).
- Returns HTTP 422 with `{"error": "File type not allowed: .<ext>"}`.

### Layer 2 — Apache Tika magic-number detection

```java
String detectedMime = tika.detect(bytes, file.getOriginalFilename());
```

- Tika reads the raw file bytes and uses a combination of magic-byte signatures and the filename as a tiebreaker.
- The detected MIME — not the client-declared `Content-Type` — is used for all downstream checks.
- Executables are rejected regardless of extension:
  ```java
  if (detectedMime.contains("executable") || "application/x-msdownload".equals(detectedMime)) {
      throw new FileSecurityException("Executable content detected");
  }
  ```
- The detected MIME is stored in `FileMetadata` and returned in `Content-Type` on download, so the browser always gets the real type.

### Layer 3 — Zip-bomb detection

For any file Tika identifies as `application/zip` or `application/x-zip-compressed`, `checkZipBomb` streams the entire decompressed content using `ZipInputStream` with an 8 KB read buffer. Two independent limits apply:

| Limit | Value | Why |
|---|---|---|
| Absolute uncompressed size | 500 MB | Caps total disk and memory impact |
| Compression ratio (uncompressed / compressed) | 100× | Catches repetitive-byte bombs that are under 500 MB compressed but extremely dense |

`ZipEntry.getSize()` is deliberately not used because it returns `-1` for DEFLATE-compressed entries — the only reliable approach is to read and count actual bytes.

### Layer 4 — Filename sanitization

`sanitizeFilename` applies three sequential transformations:

1. Replace any character outside `[a-zA-Z0-9._-]` with `_` — removes `/`, `\`, null bytes, shell metacharacters, and HTML special characters.
2. Collapse consecutive dots (`..+`) to a single dot — prevents double-extension attacks like `malware.php.jpg`.
3. Replace a leading dot with `_` — prevents hidden-file creation on Unix (`.htaccess` → `_htaccess`).

The sanitized name is stored in the database for display and `Content-Disposition` headers only. **The on-disk file is always named by a UUID** (`FileService.upload` line ~60), making path traversal impossible regardless of what filename is supplied.

---

## 4. File upload defences — what is missing and how to add it

### 4.1 Antivirus scanning (ClamAV)

**Current state:** `ScanStatus` is set to `CLEAN` immediately at upload time. `FileController.rescan` is a stub that re-returns existing metadata without scanning.

**Why it matters:** Tika detects known executable formats, but it cannot detect novel malware embedded in PDFs, Office documents, or image files. ClamAV catches known signatures in any file type.

**How to add it:**

1. Run ClamAV with the Unix socket enabled:
   ```bash
   # docker-compose.yml
   clamav:
     image: clamav/clamav:latest
     volumes:
       - /var/run/clamav:/var/run/clamav
   ```
2. Add the `clamav4j` dependency to `pom.xml`.
3. In `FileService.upload`, set `scanStatus = ScanStatus.PENDING` before saving.
4. After saving, publish an `ApplicationEvent` or use `@Async` to call the scan on a background thread.
5. Implement `FileController.rescan` to call ClamAV, update `scanStatus` to `CLEAN` or `INFECTED`, and delete the file from disk if infected.
6. Optionally block download of files in `PENDING` or `INFECTED` state by adding a check in `FileService.download`.

### 4.2 Image re-encoding (content disarm and reconstruction)

**Current state:** Image files are stored and served as-is.

**Why it matters:** A PNG or JPEG can contain malicious payloads in EXIF data or steganographically embedded content. Re-encoding strips all metadata and ensures the file is structurally clean.

**How to add it:** After the Tika check, detect image MIME types and pass the bytes through a library such as `thumbnailator` or `ImageIO`:

```java
if (detectedMime.startsWith("image/")) {
    bytes = reEncode(bytes); // strips EXIF, re-serializes pixels
}
```

This is especially important if the application allows SVG uploads (do not — SVG is XML and can contain JavaScript).

### 4.3 Blocking additional dangerous MIME types

The current extension block does not cover all dangerous file types. Add these to `BLOCKED_EXTENSIONS` or add MIME-based checks in `validateAndGetMimeType`:

| Extension | MIME type | Risk |
|---|---|---|
| `html`, `htm`, `svg` | `text/html`, `image/svg+xml` | Stored XSS when served back to browsers |
| `php`, `jsp`, `aspx` | Various | Server-side execution if the web server is misconfigured |
| `xml` | `application/xml` | XXE injection if parsed by a downstream service |
| `js`, `ts` | `application/javascript` | Execution in browser if served with wrong Content-Type |

To block by MIME type (covering renamed files):

```java
private static final Set<String> BLOCKED_MIME_TYPES = Set.of(
    "text/html", "application/javascript", "image/svg+xml", "application/xml"
);

if (BLOCKED_MIME_TYPES.contains(detectedMime)) {
    throw new FileSecurityException("File content type not allowed: " + detectedMime);
}
```

### 4.4 Rate limiting uploads

**Current state:** No rate limiting. A single authenticated user can upload files continuously.

**How to add it:** Add `spring-boot-starter-cache` and a counter per user+window, or use a filter based on Bucket4j:

```xml
<dependency>
    <groupId>com.github.vladimir-bukhtoyarov</groupId>
    <artifactId>bucket4j-core</artifactId>
    <version>8.x</version>
</dependency>
```

### 4.5 Serving files from an isolated origin

**Current state:** Files are served from the same origin as the application (`/api/files/{id}`).

**Why it matters:** If a user uploads an `text/html` file and it is served with `Content-Type: text/html` from the main origin, the browser renders it as HTML within the application's origin — enabling stored XSS even if filenames are escaped.

**Fix (defence-in-depth, apply all three):**
1. Set `Content-Disposition: attachment` on all downloads (already done in `FileController`).
2. Add a `Content-Security-Policy` header that blocks inline scripts on the main application.
3. Serve user-uploaded files from a separate subdomain (e.g., `files.example.com`) with a restrictive `Content-Security-Policy: default-src 'none'`.

---

## 5. Access control

### What is implemented

- `FileService.findWithAccess` enforces ownership on every file operation: a `ROLE_USER` can only access files where `fileMetadata.owner.username == caller`.
- `ROLE_ADMIN` bypasses the ownership check and has exclusive access to `GET /api/files/all`.
- The `isAdmin` boolean is derived from `Authentication.getAuthorities()` in the controller and passed to the service, keeping service methods testable without a security context.
- `GlobalExceptionHandler` maps `AccessDeniedException` to HTTP 403.

### Known gaps

| Gap | Risk | Fix |
|---|---|---|
| No `ROLE_ADMIN` promotion endpoint is protected | If an endpoint to set roles is added without a role check, privilege escalation is trivial | Any endpoint that modifies user roles must be guarded with `.hasRole("ADMIN")` in `SecurityConfig` or `@PreAuthorize("hasRole('ADMIN')")` on the method |
| `@EnableMethodSecurity` is on but not used | Dead configuration; not a vulnerability but easy to misunderstand | Either remove the annotation or use `@PreAuthorize` on sensitive service methods for defence-in-depth |
| No row-level security in the DB | A compromised application layer could query any row | Add PostgreSQL row-level security policies on `file_metadata` in production |

---

## 6. Injection and XSS

### SQL injection

Spring Data JPA with parameterized JPQL queries is used throughout. No string-concatenated SQL exists. The derived query `findByOwnerUsername` generates parameterized SQL automatically.

**Risk:** Low. Only increase if raw `@Query` with string concatenation is added in future.

### Path traversal

Two independent controls prevent path traversal:
1. `sanitizeFilename` removes `/`, `\`, and `..` sequences from the original filename.
2. `FileService.upload` stores the file under a UUID, making the original filename irrelevant to the filesystem path.

**Risk:** Very low. Both controls would have to fail simultaneously for a traversal to succeed.

### Stored XSS

The frontend sanitizes all server-returned strings before DOM insertion:

```javascript
// app.js
function escHtml(s) { ... }   // escapes < > & " ' for text nodes
function escAttr(s) { ... }   // escapes for attribute values
```

`FileMetadataDto` omits `storagePath` and the UUID filename — no internal paths are ever sent to the browser.

`Content-Disposition: attachment` on downloads prevents the browser from rendering uploaded HTML as a page.

**Remaining risk:** If a future endpoint renders original filenames via Thymeleaf expressions or unescaped JavaScript interpolation, XSS is possible. All new UI code must use `escHtml()` / `escAttr()` for any value derived from the server.

### XXE (XML external entity)

Apache Tika parses many file formats internally, including XML-based formats (DOCX, XLSX, SVG). Tika's `DefaultHandler` uses a SAX parser configured to disable external entity resolution. No application code directly instantiates `DocumentBuilder` or `XMLReader`.

**Risk:** Low, provided Tika is kept up to date.

---

## 7. Account brute-force and lockout

### What is implemented

- `AuthService.login` increments `User.failedAttempts` on every `BadCredentialsException`.
- When `failedAttempts >= app.max-login-attempts` (default: 5), `accountLocked` is set to `true`.
- Locked accounts are rejected immediately at the start of `AuthService.login` before any authentication attempt, returning HTTP 423.
- `UserDetailsServiceImpl` propagates `accountLocked` to `UserDetails.isAccountNonLocked()`, so Spring Security's own machinery also rejects them.

### Known gaps

| Gap | Fix |
|---|---|
| No automatic unlock after a time window | Add a `lockoutExpiry` timestamp to `User`; check it in `AuthService.login` and `UserDetailsServiceImpl` |
| Failed attempts are per-username, not per-IP | An attacker can spray across many accounts from one IP | Add an IP-based rate limiter (Bucket4j or a servlet filter) in addition to the per-account counter |
| No admin endpoint to unlock accounts | Locked users cannot recover without direct DB access | Add `POST /api/admin/users/{id}/unlock` guarded with `ROLE_ADMIN` |

---

## 8. Transport security

### What is missing (demo only)

This application ships with no TLS configuration. In production, **all traffic must be over HTTPS**.

**Options:**

1. **Reverse proxy (recommended):** Put the application behind nginx or an AWS/GCP load balancer that terminates TLS, then forward plain HTTP to the application internally.

2. **Spring Boot embedded TLS:** Provide a keystore in `application-prod.properties`:
   ```properties
   server.ssl.key-store=classpath:keystore.p12
   server.ssl.key-store-password=${KEYSTORE_PASSWORD}
   server.ssl.key-store-type=PKCS12
   ```

3. **Let's Encrypt + Certbot:** Auto-renewing certificates with nginx.

**HTTP security headers to add** (add in `SecurityConfig` or nginx):

| Header | Recommended value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Prevents HTTP downgrade after first HTTPS visit |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'` | Restricts resource loading, blocks inline scripts |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disables unused browser APIs |

Add them to `SecurityConfig`:
```java
.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
    .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
    .permissionsPolicy(pp -> pp.policy("camera=(), microphone=()")))
```

---

## 9. Secrets management

### What is implemented

`application-prod.properties` is gitignored and expected to reference environment variables:
```properties
app.jwt-secret=${JWT_SECRET}
spring.datasource.password=${DB_PASSWORD}
```

### Guidance for production

- **Never commit secrets to version control.** The `.gitignore` already excludes `application-prod.properties`; confirm this before each release.
- **Use a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) rather than environment variables where possible. Spring Cloud Vault or AWS Parameter Store integrations are available.
- **Rotate `app.jwt-secret` regularly.** Rotation invalidates all outstanding JWTs; coordinate with a deployment window or implement a dual-key rollover.
- **Database credentials:** Use a separate DB user with `INSERT`, `SELECT`, `UPDATE`, `DELETE` only — no `DROP`, `ALTER`, or `GRANT`.

---

## 10. Dependency and supply-chain hygiene

### Current dependencies with security relevance

| Dependency | Version | Notes |
|---|---|---|
| `spring-boot-starter-security` | 3.2.x | Keep on the latest Spring Boot 3.x patch; subscribe to [Spring Security advisories](https://spring.io/security) |
| `jjwt-api` / `jjwt-impl` | 0.12.x | jjwt 0.12 is the current stable line; `0.9.x` is EOL and has known vulnerabilities |
| `tika-core` | 2.9.x | Tika parses many file formats; keep patched to receive CVE fixes |
| `h2` | 2.x | H2 2.x fixed several critical RCEs present in 1.x; never expose the H2 console in production |

### Automated checks

Add the OWASP Dependency-Check plugin to `pom.xml` to scan for known CVEs on every build:

```xml
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.x</version>
    <executions>
        <execution>
            <goals><goal>check</goal></goals>
        </execution>
    </executions>
</plugin>
```

Run with:
```bash
./mvnw dependency-check:check
```

---

## 11. Production hardening checklist

Use this checklist before deploying to a production environment.

### Authentication
- [ ] `app.jwt-secret` is set to a random 32+ character secret from a CSPRNG (not the default placeholder)
- [ ] JWT expiry is set to a value appropriate for the use case (shorter is safer)
- [ ] JWT is stored in `HttpOnly` cookies, not `localStorage`
- [ ] CSRF protection is enabled for cookie-based auth
- [ ] Token revocation list (e.g. Redis-backed JTI blocklist) is in place

### File upload
- [ ] `app.max-file-size-mb` is set to the smallest acceptable value
- [ ] `spring.servlet.multipart.max-file-size` and `max-request-size` are set to match
- [ ] ClamAV (or equivalent AV) is integrated and files are not downloadable until scan completes
- [ ] HTML, SVG, JavaScript, and XML are in the blocked MIME/extension list
- [ ] User-uploaded files are served from a separate domain or subdomain
- [ ] `Content-Disposition: attachment` is set on all download responses (already done)
- [ ] Upload directory is outside the web root and not served statically

### Access control
- [ ] No endpoint exists that can elevate a user to `ROLE_ADMIN` without itself requiring `ROLE_ADMIN`
- [ ] `GET /h2-console/**` is blocked in production (`spring.h2.console.enabled=false` in `application-prod.properties`)

### Transport
- [ ] All traffic is served over HTTPS
- [ ] `Strict-Transport-Security` header is set
- [ ] `Content-Security-Policy` header is set
- [ ] `X-Content-Type-Options: nosniff` is set

### Secrets
- [ ] No secrets are in source control
- [ ] Database user has minimal privileges (no DDL)
- [ ] Secrets are sourced from environment variables or a secrets manager

### Monitoring
- [ ] Failed login attempts are logged and alerted on
- [ ] 422 upload rejections are logged (indicates active probing)
- [ ] 403 access-denied responses are logged
- [ ] Disk usage on `app.upload-dir` is monitored

### Dependencies
- [ ] OWASP Dependency-Check runs in CI and fails on high-severity CVEs
- [ ] H2 console is disabled (`spring.h2.console.enabled=false`)
- [ ] All dependencies are on supported, patched versions
