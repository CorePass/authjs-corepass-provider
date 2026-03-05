/**
 * Azure Table Storage migration: ensure the table exists.
 * Azure Tables has no DDL; Auth.js and CorePass use the same table (partitionKey + rowKey).
 * Run once so the table is created; then TableStorageAdapter and corepassAzureTablesAdapter use it.
 *
 * @param client - Table client with createTable() (e.g. @azure/data-tables TableClient for your table name)
 */

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
