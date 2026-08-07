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
   chunks). Image, video and audio files remain in an unserved quarantine directory while
   privacy metadata is removed; only the sanitized result is atomically moved to its public,
   generated filename. Still JPEG, PNG, WebP, GIF and AVIF images are decoded, auto-oriented,
   converted to sRGB, stripped and re-encoded. JPEG/WebP/AVIF use configurable lossy quality
   (78 by default); preserved PNG remains lossless so transparent screenshots are not damaged.
   The output format defaults to `preserve`, while deployments can opt into AVIF/WebP/JPEG;
   a transparent image is never silently flattened into JPEG. GIF, WebP and AVIF animations
   are decoded and re-encoded frame-by-frame with their delay/loop information retained.
   APNG currently fails closed because the pinned encoder would flatten it. MP4/M4A user
   data, free/skip padding, handler names and timestamps, plus WebM identifying fields,
   tags, attachments and Void payloads are scrubbed. Unknown nested/vendor metadata fails
   closed rather than being copied unchanged.
   When staged uploads are enabled, the asset starts as `pending` with an expiry time. Served
   files include `X-Content-Type-Options: nosniff`.
4. Server returns a public `/media/files/{generatedName}` URL plus `assetId`, `state`, and `expiresAt`.
5. Frontend sends that URL in a supported Gateway content/profile/message mutation.
   The domain service authorizes ownership before persistence, then its durable outbox
   attaches a stable parent reference through the signed internal Upload API. Message
   thumbnails and profile/group artwork slots are separate references too.
6. Detach removes only the named parent. Parent-aware authorization creates a bounded
   reservation for that exact reference even while other parents are active; only its
   matching attach can claim it. Once the final active/pending reference is gone, the
   configurable exact-reference grace (zero by default) writes a minimal tombstone before
   removing public bytes. Tombstoned paths are denied and served responses use
   `Cache-Control: private, no-store`, so cleanup can safely retry an interrupted physical
   unlink. Deleted tombstones retain no owner or parent-reference identifiers. Exact release
   history on live assets is compacted into a conservative time floor once its bounded
   map fills; operations at/below that floor fail closed unless an unexpired reservation for
   the same reference proves it was authorized earlier. This lets the final detach drain
   without reintroducing the unsafe wildcard-delete behavior. Legacy URL-only rows remain
   pinned/deferred conservatively.
7. Truly abandoned pending uploads are tombstoned and removed in two phases. Old unlocked
   quarantine and atomic-metadata temporary files are also swept after a bounded age. Missing, corrupt and
   pre-v2/wildcard-watermark/unreconciled metadata fails conservatively and is retained for operator repair;
   cleanup never treats an unreadable record as proof that no parent exists.

Batch upload is available at `POST /media/upload-multiple` with up to 10 files.

A staged upload is finalized with `POST /media/assets/finalize`.

The authenticated owner may cancel a still-pending upload with `DELETE /media/assets/{assetId}`.
Internal lifecycle calls use signed `POST /internal/media/finalize` and
`POST /internal/media/delete` requests with timestamp, nonce and HMAC headers; the raw
legacy secret header is disabled in managed environments.

Current internal lifecycle calls send bounded `references` entries containing `url`, a stable,
service-namespaced `referenceId`, and optionally the expected GUID `assetId`, plus the required outbox
operation timestamp. Missing or excessive future-skew is rejected rather than clamped. Calls are idempotent and reject
an invalid/foreign/unreadable batch before mutating any member. Legacy URL-only rows remain supported
for rolling deployment but are pinned/deferred conservatively rather than allowed to destroy an asset
with unknown parents. Both forms accept an optional `ownerUserId`; when supplied, ownership must match.
Domain services validate client-supplied URLs up front with `POST /internal/media/authorize`
(`{ ownerUserId, urls }` → `{ authorized, unauthorizedUrls }`) so a user cannot attach — and later
destroy — media belonging to somebody else. Authorization creates a bounded lease; successful attach
claims it, while lifecycle outboxes retain transient media events for capped-backoff retries.

Reference-aware callers may send those same `references` plus `operationAt` to the authorize
endpoint. Upload then reserves each exact parent independently, including while other parents
are active, and an attach clears only its matching lease. The default exact lease is seven
days so a prolonged attach-outbox outage does not race the normal pending cleanup window;
it remains bounded so a failed domain mutation cannot pin storage permanently. URL-only authorization remains a
rolling-deployment compatibility lease and is deliberately more conservative.

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
- Removes location, capture time, device/application and free-form metadata from every
  accepted image/audio/video container before publishing its URL.
- Bounds native image work to two concurrent jobs, 60 seconds, 1,000 animation frames,
  50 million cumulative pixels and 200 MiB decoded bytes by default. The ImageMagick
  native dependency is Apache-2.0 and ships a musl runtime for the Alpine container.

## Image Transcoding Policy

The `UploadStorage` section exposes:

- `ImageLossyQuality` (`60..95`, default `78`);
- `PreferredStillImageFormat` (`preserve`, `avif`, `webp` or `jpeg`);
- `MaxImageDimension`, `MaxImagePixels`, `MaxDecodedImageBytes` and
  `MaxAnimatedImageTotalPixels` for decoder resource limits;
- `MaxStoredImageDimension` for an aspect-preserving Lanczos downscale (default `6144`),
  independently of the larger decoder safety cap.

`preserve` is the conservative default while image quality/storage trade-offs are being
evaluated. To make new still uploads use AVIF at quality 78 without changing application
code, set `UploadStorage__PreferredStillImageFormat=avif`.

## Tests

```powershell
dotnet test .\Upload-Server.Tests\Upload-Server.Tests.csproj
```
