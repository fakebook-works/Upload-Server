# Full-System Docker Compose Design

## Goal

Deploy the currently supported Fakebook system with one root `docker-compose.yml`, without changing API Gateway or other backend source code.

## Scope

Default stack:

- PostgreSQL with pgvector
- Redis
- Authentication
- SocialGraph
- Recommendation
- Payment
- API Gateway
- Upload Server
- Frontend

Search, Messaging, and Notification are not composed into the current Gateway and have no working frontend contract. They may be added under an opt-in `future` profile, but they must not make the default demo stack unhealthy.

## Architecture

The existing `gateway.far` stores subgraph transport URLs using `localhost` ports. To preserve that archive without editing Gateway, API Gateway, Authentication, SocialGraph, Recommendation, and Payment share one Docker network namespace. Each process listens on its documented unique port:

- Gateway: `5000`
- Authentication: `5001`
- Payment: `5016`
- SocialGraph: `5223`
- Recommendation: `8000`

The Gateway service owns published ports for this shared namespace. PostgreSQL, Redis, Upload Server, and Frontend use the normal Compose network.

Upload Server stays outside Gateway. Frontend uploads directly to Upload Server. Upload Server validates JWT locally and validates the live session through Authentication at `http://gateway:5001/graphql`. Returned media URLs are stored through supported Gateway post/story mutations.

## Images

Existing Dockerfiles are used where present. Services without Dockerfiles use Compose `dockerfile_inline`, keeping deployment controlled by the single Compose file:

- SocialGraph: .NET 8 multi-stage build
- Recommendation: Python runtime with production requirements
- Upload Server: .NET 8 multi-stage build
- Frontend: Node build plus Nginx static runtime

Frontend build arguments use browser-reachable URLs (`localhost`), not Docker DNS names.

## Data and Initialization

PostgreSQL uses a persistent named volume and the pgvector PostgreSQL 16 image. Existing idempotent schema files initialize Authentication, Recommendation, Payment, Messaging, and Search data where applicable. Compose also initializes the missing SocialGraph schema/tables.

Redis uses a persistent volume. Uploaded media uses a dedicated persistent volume mounted into Upload Server.

## Configuration

Secrets and deploy-specific values come from a root `.env` file and Compose variable expansion. Required values:

- `POSTGRES_PASSWORD`
- `JWT_SIGNING_KEY` (minimum 32 bytes; shared by Authentication, Gateway, Upload Server)
- `GATEWAY_SHARED_SECRET` (minimum 32 bytes; shared by Gateway and composed subgraphs)
- `PAYMENT_AUTH_SECRET` (minimum 32 bytes)
- optional SMTP and PayOS credentials

Safe defaults may be provided only for local non-production ports and feature flags. No real secret is committed.

## Startup and Health

Database and Redis health checks gate dependent services. Service health checks use their existing health/GraphQL endpoints where reliable. Gateway starts before namespace-sharing subgraphs because it owns their namespace; health checks tolerate subgraph warm-up. Frontend starts after Gateway and Upload Server are healthy.

Payment remains disabled unless PayOS credentials and `PAYMENTS_ENABLED=true` are supplied.

## Verification

Required checks:

1. `docker compose config` succeeds with a safe test environment.
2. Images build successfully.
3. `docker compose up -d` reaches healthy/running state.
4. PostgreSQL, Redis, Gateway, Authentication, SocialGraph, Recommendation, Payment, Upload Server, and Frontend endpoints respond.
5. Frontend login/feed/upload flow is smoke-tested where seeded user data permits.
6. `docker compose down` stops the stack without deleting persistent volumes.

## Constraints

- Do not modify API Gateway or other backend source.
- Only Frontend, Upload Server, and root deployment configuration may change.
- Do not claim Search, Messaging, or Notification frontend support until Gateway/public APIs exist.
- Do not expose or commit development secrets.
