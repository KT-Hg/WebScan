import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { loadConfig } from "./config.ts";

const valid = {
  DATABASE_URL: "mysql://u:p@localhost:3306/webscan",
  SESSION_SECRET: "x".repeat(32),
};

test("valid env parses with defaults", () => {
  const config = loadConfig(valid);
  assert.equal(config.PORT, 8888);
  assert.equal(config.NODE_ENV, "development");
});

test("missing vars are all named in one error", () => {
  assert.throws(() => loadConfig({}), (err: Error) => {
    assert.match(err.message, /DATABASE_URL/);
    assert.match(err.message, /SESSION_SECRET/);
    return true;
  });
});

test("rejects short secret and non-mysql URL", () => {
  assert.throws(() => loadConfig({ ...valid, SESSION_SECRET: "short" }), /SESSION_SECRET/);
  assert.throws(() => loadConfig({ ...valid, DATABASE_URL: "postgres://u:p@h/db" }), /DATABASE_URL/);
});

test("web process exits non-zero and names the missing vars", () => {
  // Clean env: `npm test` loads .env into process.env, which must not leak in here.
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot };
  const result = spawnSync(process.execPath, ["src/web.ts"], { env, encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /DATABASE_URL/);
  assert.match(result.stderr, /SESSION_SECRET/);
});
