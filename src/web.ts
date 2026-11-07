import express from "express";
import { sql, type Kysely } from "kysely";
import { loadConfig } from "./config.ts";
import { createDb, type DB } from "./db.ts";

export function createApp(db: Kysely<DB>): express.Express {
  const app = express();
  app.disable("x-powered-by");

  app.get("/healthz", async (_req, res) => {
    try {
      await sql`select 1`.execute(db);
      res.json({ db: "ok" });
    } catch {
      res.status(503).json({ db: "down" });
    }
  });

  return app;
}

if (import.meta.main) {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }
  const db = createDb(config.DATABASE_URL);
  const server = createApp(db).listen(config.PORT, () => {
    console.log(`web listening on http://localhost:${config.PORT}`);
  });
  // PID 1 in a container ignores SIGTERM without a handler.
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => server.close(() => void db.destroy()));
  }
}
