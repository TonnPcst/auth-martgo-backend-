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
| `POST /api/v1/auth/login/verify`, `/resend` | anyone (rate limited), second step for users with a phone |
| `GET /api/v1/auth/me`       | any logged-in user |
| `POST /api/v1/auth/logout`  | any logged-in user (revokes all their tokens) |
| `/api/v1/users` (CRUD)      | admin |
| `GET /healthz`              | anyone |

## API docs

With the service running, open **http://localhost:8081/docs** for Swagger UI.
The spec is [api/openapi.yaml](api/openapi.yaml) (served at `/docs/openapi.yaml`),
written by hand. Check it with `make lint-api`. Set `ENABLE_DOCS=false` to hide it.

## SMS login codes

A user with a `phone` must confirm each login with a 6-digit code sent by SMS.
`POST /auth/login` then answers `202` with a `challenge_id` instead of a token,
and `POST /auth/login/verify` with the code returns the token. Users without a
phone log in in one step as before. Admins set or remove (`""`) the phone with
`PATCH /api/v1/users/{id}`.

- Codes live in Redis (`otp:login:{challenge_id}`, hashed), expire after 5 minutes,
  work once, and are dropped after 5 wrong tries. Wrong codes count toward the
  login lockout. A resend is allowed after 60 seconds, at most 3 SMS per login.
- `SMS_PROVIDER=log` (default) prints the SMS to the server log instead of sending it.
  It is refused when `APP_ENV=production`.
- `SMS_PROVIDER=telbiz` sends through [Telbiz](https://telbiz.la) with
  `TELBIZ_CLIENT_ID` and `TELBIZ_SECRET`. Phones must be Lao numbers
  (`020 xxxx xxxx` or `030 xxx xxxx`); they are stored as `20xxxxxxxx`.
  Each correct password sends a paid SMS; when the Telbiz balance is empty,
  logins for users with a phone fail with 500 (`CREDIT_NOT_SUFFICIENT` in the log).

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
