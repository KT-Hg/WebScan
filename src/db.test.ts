import assert from "node:assert/strict";
import { after, test } from "node:test";
import { NO_MIGRATIONS } from "kysely/migration";
import { createDb, createMigrator } from "./db.ts";

const url = process.env.TEST_DATABASE_URL ?? assert.fail("TEST_DATABASE_URL is required (see .env.example)");
const db = createDb(url);
const migrator = createMigrator(db);
after(() => db.destroy());

// Every migration must apply, fully roll back, and re-apply cleanly.
test("migrations round-trip: latest -> none -> latest", async () => {
  const reset = await migrator.migrateTo(NO_MIGRATIONS);
  assert.ifError(reset.error);

  const up = await migrator.migrateToLatest();
  assert.ifError(up.error);
  const all = await migrator.getMigrations();
  assert.ok(all.length > 0);
  assert.ok(all.every((m) => m.executedAt), "all migrations executed");

  const down = await migrator.migrateTo(NO_MIGRATIONS);
  assert.ifError(down.error);
  assert.ok((await migrator.getMigrations()).every((m) => !m.executedAt), "all migrations rolled back");

  const again = await migrator.migrateToLatest();
  assert.ifError(again.error);
});
