# Fakebook Upload Server

Standalone upload service for Fakebook media. This repo is intentionally separate from the API Gateway and backend services.

## Local Run

Create `appsettings.Development.json` from `appsettings.example.json` and configure:

- `Jwt:PublicKeyBase64` and `Jwt:KeyId`: Auth's RS256 public key and matching `kid`.
- `AuthService:Url`: Authentication GraphQL endpoint.
- `Cors:AllowedOrigins`: frontend origins allowed to upload directly.
- `UploadStorage:RootPath`: persistent media directory.

```powershell
dotnet run --launch-profile http
```

Default URL: `http://localhost:4001`

## Flow

1. Authenticated frontend sends `multipart/form-data` directly to `POST /media/upload`; field name is `file`.
2. Upload Server validates the JWT locally, then validates the live session through Authentication `me { userId }`.
3. Server checks the allowlisted extension/content type and magic bytes, then audits the
   complete bounded stream for active-content tokens (including tokens split across read
   chunks) before storing it under a generated filename. When staged uploads are enabled,
   the asset starts as `pending` with an expiry time. Served files include
   `X-Content-Type-Options: nosniff`.
4. Server returns a public `/media/files/{generatedName}` URL plus `assetId`, `state`, and `expiresAt`.
5. Frontend sends that URL in a supported Gateway content/profile/message mutation.
   SocialGraph or Messenger persists the parent and reliably finalizes the asset through
   the internal Upload API.
6. Pending assets that never reach a successful domain mutation are removed by the
   cleanup worker. SocialGraph deletes an asset after its final `Contained` parent is
   removed; Messenger deletes it after its final non-deleted message reference is gone.

Batch upload is available at `POST /media/upload-multiple` with up to 10 files.

A staged upload is finalized with `POST /media/assets/finalize`.

The authenticated owner may cancel a still-pending upload with `DELETE /media/assets/{assetId}`.
Internal lifecycle calls use signed `POST /internal/media/finalize` and
`POST /internal/media/delete` requests with timestamp, nonce and HMAC headers; the raw
legacy secret header is disabled in managed environments.

Both internal lifecycle calls accept an optional `ownerUserId`. When it is supplied the server only
finalizes or deletes assets whose recorded owner matches, and refuses assets whose ownership cannot
be established; callers omit it only for cascade cleanup of URLs already held in their own state.
Domain services validate client-supplied URLs up front with `POST /internal/media/authorize`
(`{ ownerUserId, urls }` → `{ authorized, unauthorizedUrls }`) so a user cannot attach — and later
destroy — media belonging to somebody else.

JWT bearer validation is configured through the options pipeline rather than reading
the signing key during top-level startup. This keeps production validation strict and
allows integration tests or environment providers to supply configuration correctly.

## Security Checks

- Rejects path traversal and non-leaf filenames.
- Rejects disallowed extensions and MIME types.
- Enforces max upload size (image max 25MB, video max 500MB, max request body 502MB).
- Requires a valid JWT and active Authentication session.
- Validates magic headers for JPEG, PNG, GIF, WebP, MP4, audio, and PDF.
- Rejects executable `MZ` payloads.
- Rejects active-content/backdoor markers such as scripts, shell execution strings, PHP, PowerShell, and command shells.
- Rejects image uploads containing SVG/HTML active markup.

## Tests

```powershell
dotnet test .\Upload-Server.Tests\Upload-Server.Tests.csproj
```
