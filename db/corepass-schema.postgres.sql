-- CorePass extension tables for Auth.js (PostgreSQL)
--
-- Apply this *in addition to* your adapter's default schema.
--
-- Tables added:
-- - corepass_identities: maps CoreID to your Auth.js userId
-- - corepass_profiles: stores CorePass-specific user metadata
-- - corepass_pending_registrations: stores passkey registrations until /passkey/data enrichment finalizes them

CREATE TABLE IF NOT EXISTS corepass_identities (
    core_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    ref_id UUID,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS corepass_profiles (
    user_id TEXT PRIMARY KEY,
    core_id TEXT NOT NULL UNIQUE,
    o18y BOOLEAN,
    o21y BOOLEAN,
    kyc BOOLEAN,
    kyc_doc TEXT,
    provided_till BIGINT,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS corepass_pending_registrations (
    token UUID PRIMARY KEY,
    credential_id TEXT NOT NULL UNIQUE,
    credential_public_key TEXT NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    credential_device_type TEXT NOT NULL,
    credential_backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT,
    email TEXT,
    ref_id UUID,
    aaguid UUID,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_corepass_pending_expires_at
    ON corepass_pending_registrations(expires_at);
