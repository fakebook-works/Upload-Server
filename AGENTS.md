# Upload Server agent rules

When embedded in the Fakebook workspace, also read the root API security contract.

- Upload is the only browser multipart exception. Require RS256 bearer validation and a
  live Authentication session.
- Keep safe leaf filename, generated GUID storage name, extension/content-type allowlist,
  magic-byte check, count/body/file caps and full-stream overlapping active-content scan.
- Keep edge and per-user rate limits and X-Content-Type-Options nosniff.
- Pending/finalize/delete/authorize operations are owner-scoped; never trust a client URL
  as ownership proof.
- Internal lifecycle APIs require signed HMAC requests and Redis nonce replay protection.
- Gateway/Upload receive only the JWT public key, never Auth's private key.
- Never log upload bytes, bearer/cookie/signature headers or storage credentials.

Run dotnet test Upload-Server.Tests/Upload-Server.Tests.csproj and add wrong-owner,
inactive-session, malformed-file, size-limit and replay tests.
