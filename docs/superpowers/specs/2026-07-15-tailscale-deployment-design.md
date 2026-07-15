# Tailscale Deployment Design

## Goal

Run Fakebook in Docker on this Windows machine, use PostgreSQL on another Tailscale machine, keep Redis local in Docker, and expose the website only to authenticated members of the same tailnet.

## Verified Environment

- Application host Tailscale IPv4: `100.110.102.23`
- Application host MagicDNS name: `rimi.tailea60ba.ts.net`
- External PostgreSQL target: `100.113.124.33:6970`
- PostgreSQL database and user: `fakebook`
- Database connection succeeds from the Windows host.
- Required schemas exist: `auth`, `messenger`, `notification`, `payment`, `recommendation`, `search`, and `social_graph`.
- Required tables and pgvector already exist. No database migration is currently required.
- Existing Tailscale Serve HTTPS port 443 configuration must remain unchanged.

## Public Entry Point

Fakebook uses a separate tailnet-only HTTPS endpoint:

```text
https://rimi.tailea60ba.ts.net:8443
```

Tailscale Serve proxies HTTPS port 8443 to a Docker edge proxy bound only to `127.0.0.1:8080`. The edge proxy routes:

- `/` to Frontend
- `/graphql` and `/api` to API Gateway
- `/socket.io` to API Gateway with WebSocket upgrade headers
- `/media` to Upload Server

Only tailnet members can reach the HTTPS endpoint. The machine's public IPv4 is not used for Fakebook traffic.

## Docker Topology

PostgreSQL is removed from Compose completely: no PostgreSQL service, image, volume, port, or initialization mounts.

Redis remains a private Docker service with a persistent volume. Backend services use Docker DNS for Redis and internal service calls.

Frontend, Gateway, Authentication, SocialGraph, Payment, Upload Server, and optional service profiles remain containerized. Recommendation stays disabled by default.

The edge proxy is the only service bound to the Windows host, at `127.0.0.1:8080`. Gateway, Authentication, SocialGraph, Payment, Upload Server, Frontend, and Redis are not published directly to LAN or public interfaces.

## Configuration

A root ignored `.env` file owns deploy-specific values:

```text
DB_HOST
DB_PORT
DB_NAME
DB_USER
DB_PASSWORD
JWT_SIGNING_KEY
GATEWAY_SHARED_SECRET
PAYMENT_AUTH_SECRET
TAILSCALE_ORIGIN
```

Database connection strings for each service use the external host and the service-owned search path:

- Authentication: `auth`
- SocialGraph: `social_graph`
- Payment: `payment`
- Search: `search`
- Messaging: `messenger`
- Recommendation: `recommendation,public`

Secrets are never copied into `docker-compose.yml`, committed documentation, browser variables, or logs.

## Browser and CORS Configuration

Frontend build variables use the single HTTPS origin:

```text
VITE_API_GATEWAY_URL=https://rimi.tailea60ba.ts.net:8443/api
VITE_GRAPHQL_GATEWAY_URL=https://rimi.tailea60ba.ts.net:8443/graphql
VITE_UPLOAD_SERVER_URL=https://rimi.tailea60ba.ts.net:8443/media
VITE_SOCKET_GATEWAY_URL=https://rimi.tailea60ba.ts.net:8443
```

Gateway and Upload Server allow exactly `https://rimi.tailea60ba.ts.net:8443`. Authentication keeps secure refresh cookies enabled because the browser connection is HTTPS.

## Database Migration Policy

Startup does not automatically apply all repository SQL files to the remote database. The current schema inventory already satisfies the required service ownership boundaries. Future migrations must be inspected and applied explicitly with `psql`, using a backup and `ON_ERROR_STOP=1`.

## Setup and Verification

Implementation will:

1. Update root Compose to use the external database and private Docker networking.
2. Create the ignored root `.env` using existing local secrets and the verified database target.
3. Statically validate Compose without starting the application stack.
4. Configure Tailscale Serve HTTPS port 8443 without modifying the existing port 443 route.
5. Provide build, start, logs, verification, stop, and Tailscale client-access commands.

Runtime container startup remains a user-run step unless the user later requests execution.

## Security Boundaries

- Tailnet access replaces public internet exposure.
- PostgreSQL remains reachable only through Tailscale and is never published by this application host.
- Backend subgraph/internal endpoints are not published to the host.
- Secure refresh cookies remain enabled.
- The edge proxy preserves request authorization headers and WebSocket upgrades.
- Real secrets stay only in ignored local configuration.
