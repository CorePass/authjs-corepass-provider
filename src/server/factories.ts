/**
 * Legacy factory exports removed. Use createCorePassServer with a unified CorePassAdapter.
 * Build the adapter by merging your Auth.js adapter with CorePass store methods
 * (e.g. use corepassPostgresAdapter, corepassD1Adapter, corepassSupabaseAdapter when available).
 */
export { createCorePassServer } from "./create-corepass-server.js"
