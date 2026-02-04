-- CorePass extension tables for Auth.js
--
-- This file intentionally does NOT include the Auth.js default tables.
-- Apply this *in addition to* your adapter's default schema.
--
-- Tables added:
-- - corepass_identities: maps CoreID to your Auth.js userId (adapter-generated or otherwise)
-- - corepass_profiles: stores CorePass-specific user metadata
-- - corepass_pending_registrations: stores passkey registrations until /passkey/data enrichment finalizes them

-- CoreID -> userId mapping
CREATE TABLE IF NOT EXISTS corepass_identities (
  core_id    TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL UNIQUE,
  ref_id     TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- CorePass user metadata (optional)
CREATE TABLE IF NOT EXISTS corepass_profiles (
  user_id       TEXT PRIMARY KEY,
  core_id       TEXT NOT NULL UNIQUE,
  o18y          INTEGER,
  o21y          INTEGER,
  kyc           INTEGER,
  kyc_doc       TEXT,
  provided_till INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  updated_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Pending registrations (default CorePass flow)
CREATE TABLE IF NOT EXISTS corepass_pending_registrations (
  token                  TEXT PRIMARY KEY,
  credential_id          TEXT NOT NULL UNIQUE, -- base64 credential id
  credential_public_key  TEXT NOT NULL,        -- base64 public key
  counter                INTEGER NOT NULL DEFAULT 0,
  credential_device_type TEXT NOT NULL,
  credential_backed_up   INTEGER NOT NULL DEFAULT 0,
  transports             TEXT,
  email                  TEXT,
  ref_id                 TEXT,
  aaguid                 TEXT,
  created_at             INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  expires_at             INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_corepass_pending_expires_at
  ON corepass_pending_registrations(expires_at);
