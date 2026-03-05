-- CorePass extension for Auth.js (SurrealDB)
-- Run with: USE NS your_ns; USE DB your_db; then paste or source this file.
-- Tables: corepass_pending, corepass_identities, corepass_profiles, corepass_authenticators (WebAuthn passkey)

DEFINE TABLE corepass_pending SCHEMAFULL;
DEFINE FIELD key ON TABLE corepass_pending TYPE string;
DEFINE FIELD payload_json ON TABLE corepass_pending TYPE string;
DEFINE FIELD expires_at ON TABLE corepass_pending TYPE int;
DEFINE FIELD created_at ON TABLE corepass_pending TYPE int;
DEFINE INDEX corepass_pending_key_unique ON TABLE corepass_pending COLUMNS key UNIQUE;

DEFINE TABLE corepass_identities SCHEMAFULL;
DEFINE FIELD core_id ON TABLE corepass_identities TYPE string;
DEFINE FIELD user_id ON TABLE corepass_identities TYPE string;
DEFINE FIELD ref_id ON TABLE corepass_identities TYPE option<string>;
DEFINE FIELD created_at ON TABLE corepass_identities TYPE int;
DEFINE FIELD updated_at ON TABLE corepass_identities TYPE int;
DEFINE INDEX corepass_identities_core_id_unique ON TABLE corepass_identities COLUMNS core_id UNIQUE;
DEFINE INDEX corepass_identities_user_id_unique ON TABLE corepass_identities COLUMNS user_id UNIQUE;

DEFINE TABLE corepass_profiles SCHEMAFULL;
DEFINE FIELD user_id ON TABLE corepass_profiles TYPE string;
DEFINE FIELD core_id ON TABLE corepass_profiles TYPE string;
DEFINE FIELD o18y ON TABLE corepass_profiles TYPE option<int>;
DEFINE FIELD o21y ON TABLE corepass_profiles TYPE option<int>;
DEFINE FIELD kyc ON TABLE corepass_profiles TYPE option<int>;
DEFINE FIELD kyc_doc ON TABLE corepass_profiles TYPE option<string>;
DEFINE FIELD provided_till ON TABLE corepass_profiles TYPE option<int>;
DEFINE FIELD created_at ON TABLE corepass_profiles TYPE int;
DEFINE FIELD updated_at ON TABLE corepass_profiles TYPE int;
DEFINE INDEX corepass_profiles_user_id_unique ON TABLE corepass_profiles COLUMNS user_id UNIQUE;

DEFINE TABLE corepass_authenticators SCHEMAFULL;
DEFINE FIELD credential_id ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD user_id ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD provider_account_id ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD credential_public_key ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD counter ON TABLE corepass_authenticators TYPE int;
DEFINE FIELD credential_device_type ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD credential_backed_up ON TABLE corepass_authenticators TYPE int;
DEFINE FIELD transports ON TABLE corepass_authenticators TYPE option<string>;
DEFINE INDEX corepass_authenticators_credential_id_unique ON TABLE corepass_authenticators COLUMNS credential_id UNIQUE;
DEFINE INDEX corepass_authenticators_user_id ON TABLE corepass_authenticators COLUMNS user_id;
