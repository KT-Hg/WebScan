import { Kysely, MysqlDialect } from "kysely";
import { Migrator, type Migration } from "kysely/migration";
import { createPool } from "mysql2";
import { loadConfig } from "./config.ts";
import * as m0001 from "./migrations/0001_init.ts";

// Tables are added here as migrations land (T3: users, T6: scans, ...).
export interface DB {}

// Static map instead of FileMigrationProvider: its dynamic import of absolute
// paths breaks on Windows (D:\ is not a valid ESM URL). One line per migration.
const migrations: Record<string, Migration> = {
  "0001_init": m0001,
};

export function createDb(databaseUrl: string): Kysely<DB> {
  return new Kysely<DB>({
    dialect: new MysqlDialect({
      pool: createPool({ uri: databaseUrl, connectTimeout: 2000, connectionLimit: 10 }),
    }),
  });
}

export function createMigrator(db: Kysely<DB>): Migrator {
  return new Migrator({ db, provider: { getMigrations: async () => migrations } });
}

// CLI: node src/db.ts up|down
if (import.meta.main) {
  const direction = process.argv[2];
  if (direction !== "up" && direction !== "down") {
    console.error("usage: node src/db.ts up|down");
    process.exit(2);
  }
  const db = createDb(loadConfig().DATABASE_URL);
  const migrator = createMigrator(db);
  const { error, results } = direction === "up" ? await migrator.migrateToLatest() : await migrator.migrateDown();
  for (const r of results ?? []) console.log(`${r.status}: ${r.migrationName} (${r.direction})`);
  if (!results?.length && !error) console.log("nothing to migrate");
  await db.destroy();
  if (error) {
    console.error(error);
    process.exit(1);
  }
}
