import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(0).max(65535).default(8888),
  DATABASE_URL: z.url({ protocol: /^mysql$/ }),
  SESSION_SECRET: z.string().min(32),
});

export type Config = z.infer<typeof schema>;

/** Parses env; throws one error naming every missing/invalid variable. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = schema.safeParse(env);
  if (result.success) return result.data;
  const problems = result.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
  throw new Error(`Invalid environment configuration:\n${problems.join("\n")}`);
}
