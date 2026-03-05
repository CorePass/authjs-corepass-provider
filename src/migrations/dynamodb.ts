/**
 * DynamoDB: key layout for the WebAuthn Authenticator table.
 * Create the table (e.g. via AWS Console, CloudFormation, or CDK) with this key design.
 * No runtime migration API in this package; use your preferred IaC or AWS SDK to create the table.
 *
 * Table: authenticators (or corepass_authenticators)
 * - Partition key: credential_id (String) — unique per passkey
 * - Attributes: user_id, provider_account_id, credential_public_key, counter (Number), credential_device_type, credential_backed_up (Number 0|1), transports (String, optional)
 *
 * For listAuthenticatorsByUserId you need a GSI:
 * - GSI: user_id-credential_id-index (or similar)
 * - Partition key: user_id (String)
 * - Sort key: credential_id (String)
 * Then implement queryAuthenticatorsByUserId on your DynamoLike client to query this GSI.
 */

export const AUTHENTICATORS_TABLE_KEY_SCHEMA_DYNAMODB = {
	tableName: "authenticators",
	partitionKey: { name: "credential_id", type: "S" as const },
	attributes: [
		{ name: "credential_id", type: "S" as const },
		{ name: "user_id", type: "S" as const },
		{ name: "provider_account_id", type: "S" as const },
		{ name: "credential_public_key", type: "S" as const },
		{ name: "counter", type: "N" as const },
		{ name: "credential_device_type", type: "S" as const },
		{ name: "credential_backed_up", type: "N" as const },
		{ name: "transports", type: "S" as const },
	],
	gsiForListByUserId: {
		indexName: "user_id-credential_id-index",
		partitionKey: { name: "user_id", type: "S" as const },
		sortKey: { name: "credential_id", type: "S" as const },
	},
} as const
