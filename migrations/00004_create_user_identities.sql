-- +goose Up
-- Links a user to an account at an outside login provider such as Google.
-- subject is the provider's stable user ID ("sub"); it does not change when the email does.
-- A user can link at most one account per provider.
CREATE TABLE user_identities (
    provider   TEXT        NOT NULL,
    subject    TEXT        NOT NULL,
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject),
    CONSTRAINT user_identities_user_provider_key UNIQUE (user_id, provider)
);

-- +goose Down
DROP TABLE IF EXISTS user_identities;
