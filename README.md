# Fakebook Upload Server

Standalone upload service for Fakebook media. This repo is intentionally separate from the API Gateway and backend services.

## Local Run

Create `appsettings.Development.json` from `appsettings.example.json` and set `Jwt:SigningKey` to the same signing key used by Fakebook auth/API gateway for local development.

```powershell
dotnet run --launch-profile http
```

Default URL: `http://localhost:5050`

## Flow

1. Authenticated frontend calls `POST /media/upload-requests` with `fileName`, `contentType`, and `size`.
2. Upload server returns a short-lived signed `/media/uploads/{uploadId}?token=...` URL.
3. Frontend uploads `multipart/form-data` with field name `file` to the signed URL.
4. Server validates and stores the file under a generated filename.
5. Server returns a public `/media/files/{generatedName}` URL.

## Security Checks

- Rejects path traversal and non-leaf filenames.
- Rejects disallowed extensions and MIME types.
- Enforces max upload size.
- Requires the upload body to match the issued upload link metadata.
- Validates magic headers for JPEG, PNG, GIF, WebP, MP4, and PDF.
- Rejects executable `MZ` payloads.
- Rejects active-content/backdoor markers such as scripts, shell execution strings, PHP, PowerShell, and command shells.
- Rejects image uploads containing SVG/HTML active markup.
