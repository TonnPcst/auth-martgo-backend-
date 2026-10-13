-- name: CreateUser :one
INSERT INTO users (email, password_hash, full_name, role)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY id
LIMIT sqlc.arg('limit')::int OFFSET sqlc.arg('offset')::int;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: UpdateUser :one
UPDATE users SET
    full_name     = COALESCE(sqlc.narg('full_name')::text, full_name),
    role          = COALESCE(sqlc.narg('role')::text, role),
    is_active     = COALESCE(sqlc.narg('is_active')::boolean, is_active),
    password_hash = COALESCE(sqlc.narg('password_hash')::text, password_hash),
    token_version = token_version + CASE
        WHEN sqlc.narg('password_hash')::text IS NOT NULL
          OR sqlc.narg('is_active')::boolean IS FALSE THEN 1
        ELSE 0 END
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: BumpTokenVersion :one
UPDATE users SET token_version = token_version + 1 WHERE id = $1
RETURNING *;
