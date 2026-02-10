# CorePass schema files

Apply the schema that matches your database **in addition to** your Auth.js adapter’s schema.

| Adapter / engine | Schema file |
| ---------------- | ----------- |
| **Postgres**, **Neon**, **Prisma** (Postgres), **Drizzle** (Postgres), **Kysely** (Postgres), **TypeORM** (Postgres), **MikroORM** (Postgres), **Sequelize** (Postgres), **Hasura** (Postgres) | `corepass-schema.postgres.sql` |
| **D1**, **SQLite** | `corepass-schema.sql` |
| **SurrealDB** | `corepass-schema.surrealdb.surql` |
| **EdgeDB** | `corepass-schema.edgedb.esdl` |
| **Neo4j**, **Fauna**, **Dgraph**, **MongoDB**, **Firebase**, **DynamoDB**, **Azure Tables**, **PouchDB**, **Upstash Redis**, **Unstorage**, **Xata** | No SQL/DDL in this folder; see each adapter’s types and docs for collection/table/key layout. |

For SQL adapters, at least the `corepass_pending` table (or equivalent) is required when using **pending.strategy "db"**.
