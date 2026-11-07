import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createDb } from "./db.ts";
import { createApp } from "./web.ts";

async function getHealth(databaseUrl: string) {
  const db = createDb(databaseUrl);
  const server = createApp(db).listen(0);
  await once(server, "listening");
  try {
    const { port } = server.address() as AddressInfo;
    const res = await fetch(`http://127.0.0.1:${port}/healthz`);
    return { status: res.status, body: await res.json() };
  } finally {
    server.close();
    await db.destroy();
  }
}

test("healthz is 200 when the database answers", async () => {
  const url = process.env.TEST_DATABASE_URL ?? assert.fail("TEST_DATABASE_URL is required (see .env.example)");
  assert.deepEqual(await getHealth(url), { status: 200, body: { db: "ok" } });
});

test("healthz is 503 when the database is unreachable", async () => {
  assert.deepEqual(await getHealth("mysql://u:p@127.0.0.1:1/none"), { status: 503, body: { db: "down" } });
});
