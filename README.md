# martgo-auth

Authentication and user management service for martgo. It owns the `users`
table, issues JWTs, and publishes each user's session state to Redis so that
[martgo-backend](https://github.com/TonnPcst/martgo-backend) (mart-api) can
check revocation without calling this service.

**Stack:** chi · PostgreSQL · pgx/pgxpool · sqlc · goose · JWT (EdDSA) · bcrypt · Redis · slog

## Endpoints

| Method & path               | Who            |
| --------------------------- | -------------- |
| `POST /api/v1/auth/login`   | anyone (rate limited) |
| `GET /api/v1/auth/me`       | any logged-in user |
| `POST /api/v1/auth/logout`  | any logged-in user (revokes all their tokens) |
| `/api/v1/users` (CRUD)      | admin |
| `GET /healthz`              | anyone |

## API docs

With the service running, open **http://localhost:8081/docs** for Swagger UI.
The spec is [api/openapi.yaml](api/openapi.yaml) (served at `/docs/openapi.yaml`),
written by hand. Check it with `make lint-api`. Set `ENABLE_DOCS=false` to hide it.

## Auth contract with mart-api

Nothing enforces these across repos. Change both sides together.

- **JWT:** signed with Ed25519 (`alg: EdDSA`), issuer `martgo-auth`.
  Claims: `uid` (int64), `role` (string), `ver` (int32), plus `sub`, `iat`, `exp`.
  This service holds `keys/jwt_private.pem`; mart-api holds only `keys/jwt_public.pem`.
- **Redis:** hash `session:user:{id}` with fields `ver`, `role`, `active` (`1`/`0`),
  expiring after `JWT_TTL`. Written on login, logout and every user update.
  mart-api rejects a token when the key is missing, `active` is `0`, or `ver`
  differs from the token's `ver`.

## Setup

Redis and the gateway run from mart-api's `docker-compose.yml`, so start that first.

```bash
cp .env.example .env
openssl genpkey -algorithm ed25519 -out keys/jwt_private.pem
openssl pkey -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem
cp keys/jwt_public.pem ../supermarket-go-backend-project/keys/

docker compose up -d   # Postgres on localhost:5434
make migrate           # create users + seed the admin
make run               # http://localhost:8081
```

Other targets: `make dev`, `make test`, `make sqlc`, `make lint-api`, `make migrate-status`, `make help`.

## Known gaps

- If the database write succeeds and the Redis write fails, the change does not
  reach mart-api (the client gets a 500). The proper fix is an outbox table.
- The login lockout (`loginGuard`) is in memory, so it is per instance. Move it
  to Redis before running more than one replica.
