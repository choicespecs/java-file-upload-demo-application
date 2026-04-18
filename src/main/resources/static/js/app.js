// Redirect to login if no JWT is present in localStorage (guards the SPA page)
const token = localStorage.getItem('jwt');
if (!token) window.location.href = '/login';

// Display the stored username in the navigation bar
document.getElementById('nav-username').textContent = localStorage.getItem('username') || '';

/**
 * Returns an Authorization header object containing the stored JWT bearer token.
 * Included on every fetch() call that requires authentication.
 */
function authHeaders() {
    return { 'Authorization': 'Bearer ' + token };
}

/**
 * Formats a byte count as a human-readable string with one decimal place.
 * Thresholds: < 1024 → bytes, < 1 MiB → kilobytes, otherwise megabytes.
 *
 * @param {number} b - Size in bytes
 * @returns {string} Formatted size string (e.g. "1.5 KB", "2.3 MB")
 */
function formatBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';    // 1024 * 1024 = 1 MiB
    return (b / 1048576).toFixed(1) + ' MB';
}

/**
 * Fetches the authenticated user's file list from the API and renders the table.
 * Shows an empty-state message when no files exist.
 * Logs out automatically on a 401 response (expired or revoked token).
 */
async function loadFiles() {
    const res = await fetch('/api/files', { headers: authHeaders() });
    if (res.status === 401) { logout(); return; }
    const files = await res.json();
    const tbody = document.getElementById('file-list');
    const empty = document.getElementById('empty-msg');
    const table = document.getElementById('file-table');
    tbody.innerHTML = '';
    if (!files.length) {
        empty.classList.remove('d-none');
        table.style.display = 'none';
        return;
    }
    empty.classList.add('d-none');
    table.style.display = '';
    files.forEach(f => {
        // Choose Bootstrap badge colour based on scan status
        const badge = f.scanStatus === 'CLEAN' ? 'bg-success'
                    : f.scanStatus === 'INFECTED' ? 'bg-danger'
                    : 'bg-warning text-dark'; // PENDING or FAILED
        const tr = document.createElement('tr');
        // escHtml() prevents stored XSS from malicious filenames or MIME types
        tr.innerHTML = `
            <td>${escHtml(f.originalFilename)}</td>
            <td><small class="text-muted">${escHtml(f.mimeType || '-')}</small></td>
            <td>${formatBytes(f.size)}</td>
            <td><span class="badge ${badge}">${f.scanStatus}</span></td>
            <td><small>${new Date(f.createdAt).toLocaleString()}</small></td>
            <td class="text-end">
                <button class="btn btn-sm btn-outline-primary me-1" onclick="downloadFile(${f.id},'${escAttr(f.originalFilename)}')">Download</button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteFile(${f.id})">Delete</button>
            </td>`;
        tbody.appendChild(tr);
    });
}

/**
 * Downloads a file by fetching its bytes and triggering a browser save dialog
 * via a programmatic anchor-click with a Blob URL.
 * The Blob URL is revoked immediately after the click to release memory.
 *
 * @param {number} id       - File database ID
 * @param {string} filename - Original filename used for the save dialog suggestion
 */
async function downloadFile(id, filename) {
    const res = await fetch(`/api/files/${id}`, { headers: authHeaders() });
    if (!res.ok) { alert('Download failed'); return; }
    const blob = await res.blob();
    // Create a temporary object URL pointing to the blob, trigger the download, then clean up
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Deletes a file after user confirmation, then refreshes the file list.
 *
 * @param {number} id - File database ID to delete
 */
async function deleteFile(id) {
    if (!confirm('Delete this file?')) return;
    const res = await fetch(`/api/files/${id}`, { method: 'DELETE', headers: authHeaders() });
    if (res.ok) loadFiles();
    else alert('Delete failed');
}

/**
 * Files at or below this threshold use the single-request upload endpoint.
 * Files above it are split into CHUNK_SIZE-byte pieces and uploaded via the
 * chunked upload API. Both thresholds must stay in sync with the backend
 * app.max-file-size-mb and app.chunk-size-mb properties.
 */
const CHUNK_THRESHOLD = 10 * 1024 * 1024;  // 10 MB — matches app.max-file-size-mb
const CHUNK_SIZE      =  5 * 1024 * 1024;  //  5 MB — matches app.chunk-size-mb

/**
 * Uploads a large file by splitting it into fixed-size chunks, sending each chunk
 * sequentially, and finalising the assembly server-side.
 *
 * Steps:
 *  1. POST /api/files/upload/init   → obtain uploadId
 *  2. POST /api/files/upload/{id}/chunk?chunkIndex=N  (repeated for each chunk)
 *  3. POST /api/files/upload/{id}/complete            → server assembles and validates
 *
 * The progress bar is updated after each successful chunk. On any error the session
 * is aborted via DELETE /api/files/upload/{id} to clean up temp files.
 *
 * @param {File} file - The File object selected by the user
 * @returns {Promise<Object>} Resolves with the FileMetadataDto on success
 * @throws {Error} On network failure, server rejection, or security validation failure
 */
async function chunkedUpload(file) {
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const progressWrap = document.getElementById('upload-progress');
    const progressBar  = document.getElementById('upload-progress-bar');
    const progressText = document.getElementById('upload-progress-text');

    progressWrap.classList.remove('d-none');
    progressBar.classList.add('progress-bar-animated');
    progressBar.style.width = '0%';
    progressBar.textContent = '0%';
    progressText.textContent = 'Initialising…';

    // Step 1 — init session
    let uploadId;
    const initRes = await fetch('/api/files/upload/init', {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, totalSize: file.size, totalChunks })
    });
    if (!initRes.ok) {
        progressWrap.classList.add('d-none');
        const err = await initRes.json();
        throw new Error(err.error || 'Failed to initialise upload');
    }
    ({ uploadId } = await initRes.json());

    // Step 2 — send chunks
    try {
        for (let i = 0; i < totalChunks; i++) {
            const start = i * CHUNK_SIZE;
            const end   = Math.min(start + CHUNK_SIZE, file.size);
            const form  = new FormData();
            form.append('chunk', file.slice(start, end));

            const chunkRes = await fetch(
                `/api/files/upload/${uploadId}/chunk?chunkIndex=${i}`,
                { method: 'POST', headers: authHeaders(), body: form }
            );
            if (!chunkRes.ok) {
                const err = await chunkRes.json();
                throw new Error(err.error || `Chunk ${i} upload failed`);
            }

            // Reserve the last 10% of the bar for the assembly/validation step
            const pct = Math.round(((i + 1) / totalChunks) * 90);
            progressBar.style.width = pct + '%';
            progressBar.textContent = pct + '%';
            progressText.textContent = `Uploading chunk ${i + 1} of ${totalChunks}…`;
        }
    } catch (err) {
        // Best-effort cleanup — ignore abort errors so the original error propagates
        fetch(`/api/files/upload/${uploadId}`, { method: 'DELETE', headers: authHeaders() })
            .catch(() => {});
        progressWrap.classList.add('d-none');
        throw err;
    }

    // Step 3 — complete (assembly + security validation happens server-side)
    progressText.textContent = 'Assembling and validating…';
    const completeRes = await fetch(`/api/files/upload/${uploadId}/complete`, {
        method: 'POST',
        headers: authHeaders()
    });
    if (!completeRes.ok) {
        fetch(`/api/files/upload/${uploadId}`, { method: 'DELETE', headers: authHeaders() })
            .catch(() => {});
        progressWrap.classList.add('d-none');
        const err = await completeRes.json();
        throw new Error(err.error || 'Failed to complete upload');
    }

    progressBar.style.width = '100%';
    progressBar.textContent = '100%';
    progressBar.classList.remove('progress-bar-animated');
    progressText.textContent = 'Complete';
    // Hide the bar after a short delay so the user can see it reach 100%
    setTimeout(() => {
        progressWrap.classList.add('d-none');
        progressBar.classList.add('progress-bar-animated');
    }, 1500);

    return completeRes.json();
}

// Upload form submit handler — branches on file size: files above CHUNK_THRESHOLD use
// the chunked path; smaller files use the single-request endpoint.
document.getElementById('upload-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const file  = document.getElementById('file-input').files[0];
    if (!file) return;
    const msgEl = document.getElementById('upload-msg');
    msgEl.className = 'alert d-none';

    try {
        if (file.size > CHUNK_THRESHOLD) {
            await chunkedUpload(file);
        } else {
            const form = new FormData();
            form.append('file', file);
            // No Content-Type header — browser sets it with the correct multipart boundary
            const res = await fetch('/api/files/upload', {
                method: 'POST', headers: authHeaders(), body: form
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || 'Upload failed');
            }
        }
        msgEl.className = 'alert alert-success';
        msgEl.textContent = 'Upload successful';
        document.getElementById('file-input').value = '';
        loadFiles();
    } catch (err) {
        msgEl.className = 'alert alert-danger';
        msgEl.textContent = err.message || 'Upload failed';
    }
});

/**
 * Clears all auth data from localStorage and redirects to the login page.
 * Called on logout button click and on 401 responses from the API.
 */
function logout() {
    localStorage.clear();
    window.location.href = '/login';
}

/**
 * Escapes a string for safe insertion as HTML text content.
 * Prevents stored XSS when displaying server-returned values (e.g. filenames).
 *
 * Escapes: & < > "
 *
 * @param {*} s - Value to escape (coerced to string)
 * @returns {string} HTML-safe string
 */
function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/**
 * Escapes single quotes in a string for safe embedding inside an HTML attribute value
 * that is delimited by single quotes (e.g. onclick="...('value')").
 *
 * Note: escHtml() should be preferred for general HTML contexts; this function is only
 * needed for the specific onclick attribute pattern in loadFiles().
 *
 * @param {*} s - Value to escape (coerced to string)
 * @returns {string} String with single quotes backslash-escaped
 */
function escAttr(s) {
    return String(s).replace(/'/g,"\\'");
}

// Load the file list immediately when the page script runs
loadFiles();
