-- name: GetUserByIdentity :one
SELECT * FROM users
WHERE id = (SELECT user_id FROM user_identities WHERE provider = $1 AND subject = $2);

-- name: CreateUserIdentity :exec
INSERT INTO user_identities (provider, subject, user_id)
VALUES ($1, $2, $3);
