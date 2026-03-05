/**
 * Azure Table Storage migration: ensure the table exists.
 * Azure Tables has no DDL; Auth.js and CorePass use the same table (partitionKey + rowKey).
 * Run once so the table is created; then TableStorageAdapter and corepassAzureTablesAdapter use it.
 *
 * @param client - Table client with createTable() (e.g. @azure/data-tables TableClient for your table name)
 */

/** Table name and authenticators entity layout: partitionKey = "AUTHENTICATOR", rowKey = credential_id. */
export const AUTHENTICATORS_TABLE_AZURE_TABLES = {
	tableName: "corepass",
	partitionKeyAuthenticators: "AUTHENTICATOR",
	rowKey: "credential_id",
	properties: {
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "number",
		credential_device_type: "string",
		credential_backed_up: "number (0 | 1)",
		transports: "string | null",
	},
	listByUserId: "Use queryEntities with partitionKey 'AUTHENTICATOR' and filter on user_id.",
} as const

export type AzureTablesMigrationClient = {
	createTable(): Promise<void>
}

export async function migrateAzureTables(client: AzureTablesMigrationClient): Promise<void> {
	try {
		await client.createTable()
	} catch (e) {
		// Table already exists (Azure returns 409 Conflict)
		if (typeof (e as { statusCode?: number }).statusCode === "number" && (e as { statusCode: number }).statusCode === 409) {
			return
		}
		if (typeof console !== "undefined" && console.warn) {
			console.warn("[corepass] Azure Tables migration (createTable):", (e as Error).message)
		}
		throw e
	}
}
