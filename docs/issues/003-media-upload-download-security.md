# Issue 003: Media Upload & Download Security — Path Traversal, MIME Bypass, and Size Enforcement

**Severity:** High  
**Domain:** Media, Security  
**Affected files:** `src/api/media.ts`

---

## Problem Statement

The media upload and download endpoints have multiple security gaps that collectively allow an attacker to upload arbitrary content (including executables disguised as images), bypass file size limits, inject malicious filenames into HTTP headers, and serve content without proper browser security headers. For a homeserver that stores and serves user-uploaded content, these are high-priority fixes.

---

## Detailed Breakdown

### 1. Content-Disposition Header Injection via Unsanitized Filename

**File:** `src/api/media.ts` (lines ~102, ~133)  
**Severity:** High

User-controlled filenames are interpolated directly into the `Content-Disposition` response header without escaping:

```typescript
headers.set('Content-Disposition', `inline; filename="${metadata.filename}"`);
headers.set('Content-Disposition', `inline; filename="${requestedFilename}"`);
```

A filename containing double quotes, newlines, or null bytes can break the header parsing:
- `test"; attachment; filename="malware.exe` — changes the browser's interpretation of the disposition type
- `test\r\nX-Custom-Header: injected` — injects arbitrary HTTP headers (header injection)
- Filenames with path separators could confuse download dialogs in some browsers

**Step-by-step fix:**
1. Strip or replace all characters outside `[a-zA-Z0-9._-]` from filenames
2. Use RFC 5987 encoding for non-ASCII filenames: `filename*=UTF-8''encoded_name`
3. Enforce a maximum filename length (255 characters)
4. Validate filenames on upload (line ~40) AND on download response generation
5. Example sanitization:
   ```typescript
   function sanitizeFilename(name: string): string {
     return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 255);
   }
   ```

---

### 2. MIME Type Whitelist Defined But Never Enforced

**File:** `src/api/media.ts` (lines ~16-32 define `SUPPORTED_TYPES`, line ~39 accepts client type)  
**Severity:** High

A comprehensive MIME type whitelist is defined at the top of the file but never referenced during upload:

```typescript
// Lines 16-32: SUPPORTED_TYPES whitelist exists
const SUPPORTED_TYPES = ['image/jpeg', 'image/png', 'image/gif', ...];

// Line 39: But the upload just trusts the client
const contentType = c.req.header('Content-Type') || 'application/octet-stream';
// contentType is stored and later served as-is
```

An attacker can upload an executable file with `Content-Type: image/png`. When another user downloads it, their browser sees the `image/png` MIME type and may behave unpredictably.

**Step-by-step fix:**
1. Validate the `Content-Type` against `SUPPORTED_TYPES` on upload — reject with 413 if not in the list
2. Additionally, perform magic-byte validation: check the first few bytes of the uploaded content match the claimed MIME type (e.g., JPEG starts with `FF D8 FF`, PNG starts with `89 50 4E 47`)
3. On download, always set `X-Content-Type-Options: nosniff` to prevent browsers from overriding the declared type
4. Consider serving user-uploaded content from a separate domain to isolate it from the main origin's cookies and auth

---

### 3. Upload Size Limit Checked via Content-Length Header Only

**File:** `src/api/media.ts` (line ~43)  
**Severity:** High

The upload endpoint checks the `Content-Length` request header against the maximum size, but this header is client-provided and can be omitted or falsified:

```typescript
const contentLength = parseInt(c.req.header('Content-Length') || '0');
if (contentLength > MAX_UPLOAD_SIZE) {
  return Errors.tooLarge('Upload exceeds maximum size').toResponse();
}

// Then reads the entire body into memory regardless
const body = await c.req.arrayBuffer();
```

A client can set `Content-Length: 100` but send a 100MB body. The server reads it entirely into memory (potentially causing OOM), and if R2 accepts it, it's stored without any size check on the actual content.

**Step-by-step fix:**
1. After reading the body, validate actual size: `if (body.byteLength > MAX_UPLOAD_SIZE) return 413`
2. Better: use a streaming approach with size-limited reading to avoid loading oversized content into memory at all
3. Keep the `Content-Length` header check as an early-exit optimization, but always verify the actual body size

---

### 4. Missing Security Response Headers on Media Endpoints

**File:** `src/api/media.ts` (all download/thumbnail responses)  
**Severity:** Medium

Media download responses are missing several security-critical headers:

- **No `X-Content-Type-Options: nosniff`** — Browsers may MIME-sniff content
- **No `Content-Security-Policy`** — Served HTML files (if uploaded) can execute scripts
- **No `Content-Length`** — Clients can't show download progress
- **No `Cache-Control`** — Media may be cached unpredictably
- **No `ETag`** — No efficient cache validation

**Step-by-step fix:**
1. Add to all media responses:
   ```typescript
   headers.set('X-Content-Type-Options', 'nosniff');
   headers.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
   headers.set('X-Frame-Options', 'DENY');
   headers.set('Content-Length', String(body.size));
   ```
2. For HTML or SVG content, override the Content-Type to `application/octet-stream` to force download rather than rendering
3. Set `Cache-Control: public, max-age=31536000, immutable` for media (Matrix media IDs are content-addressed)

---

### 5. Thumbnail Dimension Parsing Can Produce NaN

**File:** `src/api/media.ts` (lines ~143-144)  
**Severity:** Low

```typescript
const width = Math.min(parseInt(c.req.query('width') || '96'), 1920);
```

If the query parameter is `?width=abc`, `parseInt('abc')` returns `NaN`, and `Math.min(NaN, 1920)` returns `NaN`, which propagates to the thumbnail generation service.

**Step-by-step fix:**
1. Parse and validate:
   ```typescript
   const width = Math.max(1, Math.min(parseInt(c.req.query('width') || '96', 10) || 96, 1920));
   ```
2. The `|| 96` fallback handles NaN; `Math.max(1, ...)` prevents zero or negative values

---

## Ideal Resolution

After these fixes:
- **Only content matching the MIME whitelist can be uploaded**, with magic-byte verification
- **Actual body size is verified** — not just the client-declared Content-Length
- **Filenames are sanitized** and encoded per RFC 5987 — no header injection possible
- **All media responses carry security headers** preventing MIME sniffing, framing, and script execution
- **Media is served with proper cache headers** for performance and correctness
