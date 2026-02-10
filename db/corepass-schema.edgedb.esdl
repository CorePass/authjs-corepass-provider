-- CorePass extension for Auth.js (EdgeDB)
-- Add this module to your dbschema (e.g. dbschema/corepass.esdl) and run: edgedb migration create && edgedb migrate
-- The adapter uses corepass::Pending, corepass::Identity, corepass::Profile

module corepass {
  type Pending {
    required property key -> str {
      constraint exclusive;
    };
    required property payload_json -> str;
    required property expires_at -> int64;
    required property created_at -> int64;
  }

  type Identity {
    required property core_id -> str {
      constraint exclusive;
    };
    required property user_id -> str {
      constraint exclusive;
    };
    property ref_id -> str;
    required property updated_at -> int64;
  }

  type Profile {
    required property user_id -> str {
      constraint exclusive;
    };
    required property core_id -> str {
      constraint exclusive;
    };
    property o18y -> int64;
    property o21y -> int64;
    property kyc -> int64;
    property kyc_doc -> str;
    property provided_till -> int64;
    required property updated_at -> int64;
  }
}
