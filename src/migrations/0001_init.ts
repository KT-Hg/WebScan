import type { Kysely } from "kysely";

// Intentionally empty: proves the migrator loads .ts migrations under Node type
// stripping and creates its bookkeeping tables. Real tables start in 0002 (T3).
export async function up(_db: Kysely<unknown>): Promise<void> {}

export async function down(_db: Kysely<unknown>): Promise<void> {}
