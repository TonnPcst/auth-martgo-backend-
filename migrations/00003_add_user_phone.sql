-- +goose Up
-- A user with a phone must confirm each login with an SMS code.
ALTER TABLE users ADD COLUMN phone TEXT UNIQUE;

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS phone;
