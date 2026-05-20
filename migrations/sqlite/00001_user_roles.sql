-- +goose Up
CREATE TABLE authz_user_roles (
    issuer      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    module      TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL,
    granted_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    granted_by  TEXT NOT NULL,
    PRIMARY KEY (issuer, subject, module, role)
);
CREATE INDEX authz_user_roles_lookup_idx ON authz_user_roles (issuer, subject);

-- +goose Down
DROP TABLE authz_user_roles;
