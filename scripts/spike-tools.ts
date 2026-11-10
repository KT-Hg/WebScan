// T2 spike: run each scanner once in a disposable container (array args, no shell)
// and save trimmed real output to test/fixtures/<tool>.json for normalizer tests.
// ponytail: throwaway script; the real runner is src/docker.ts (T7).
//
//   docker compose --profile lab --profile sonar up -d juice-shop sonarqube
//   npm run spike                      # all four tools
//   npm run spike -- zap trivy         # a subset
//   npm run spike -- trivy-private     # needs SPIKE_PRIVATE_REPO + GITHUB_TOKEN in .env
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import Docker from "dockerode";

const docker = new Docker();
const NETWORK = "webscan-net"; // compose.yaml fixes this name
const IMAGES = {
  zap: "ghcr.io/zaproxy/zaproxy:2.17.0",
  wapiti: "webscan/wapiti:3.3.2", // docker build -t webscan/wapiti:3.3.2 docker/wapiti
  trivy: "aquasec/trivy:0.76.2",
  git: "alpine/git:v2.54.0",
  scanner: "sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1",
};
const DAST_TARGET = process.env.SPIKE_DAST_TARGET ?? "http://juice-shop:3000";
// Needs a lockfile: Trivy resolves npm vulns from package-lock.json, not package.json.
const SAST_REPO = process.env.SPIKE_SAST_REPO ?? "https://github.com/snyk-labs/nodejs-goof";
const SONAR_HOST = "http://127.0.0.1:9000"; // from this script
const SONAR_IN_NET = "http://sonarqube:9000"; // from scan containers
const PROJECT_KEY = "ws-spike";

interface RunSpec {
  image: string;
  cmd: string[];
  env?: string[];
  mountAt?: string; // fresh per-run volume mounted here
  binds?: string[]; // extra named volumes
  user?: string;
  entrypoint?: string[];
  readFile?: string; // file to copy out after exit
  timeoutMs: number;
}
interface RunResult {
  exitCode: number;
  seconds: number;
  logs: string;
  file?: Buffer;
}

async function run(name: string, spec: RunSpec): Promise<RunResult> {
  const volume = `ws-spike-${name}-${Date.now()}`;
  const binds = [...(spec.binds ?? []), ...(spec.mountAt ? [`${volume}:${spec.mountAt}`] : [])];
  const container = await docker.createContainer({
    Image: spec.image,
    Cmd: spec.cmd,
    Env: spec.env,
    User: spec.user,
    Entrypoint: spec.entrypoint,
    HostConfig: { NetworkMode: NETWORK, Binds: binds, Memory: 3 * 1024 ** 3 },
  });
  const started = Date.now();
  try {
    await container.start();
    const timer = setTimeout(() => void container.kill().catch(() => {}), spec.timeoutMs);
    const { StatusCode } = await container.wait();
    clearTimeout(timer);
    const logs = demux((await container.logs({ stdout: true, stderr: true })) as unknown as Buffer);
    const file = spec.readFile ? await copyOut(container, spec.readFile).catch(() => undefined) : undefined;
    return { exitCode: StatusCode, seconds: Math.round((Date.now() - started) / 1000), logs, file };
  } finally {
    await container.remove({ force: true });
    if (spec.mountAt) await docker.getVolume(volume).remove().catch(() => {});
  }
}

// Non-TTY logs are framed: [stream, 0, 0, 0, size(uint32 BE)] + payload.
function demux(buf: Buffer): string {
  let out = "";
  for (let i = 0; i + 8 <= buf.length; ) {
    const size = buf.readUInt32BE(i + 4);
    out += buf.subarray(i + 8, i + 8 + size).toString("utf8");
    i += 8 + size;
  }
  return out;
}

// getArchive returns a tar stream; pull out the first regular file.
async function copyOut(container: Docker.Container, path: string): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of await container.getArchive({ path })) chunks.push(chunk as Buffer);
  const tar = Buffer.concat(chunks);
  for (let off = 0; off + 512 <= tar.length; ) {
    if (tar[off] === 0) break; // end-of-archive block
    const size = parseInt(tar.toString("ascii", off + 124, off + 136).replace(/\0/g, "").trim() || "0", 8);
    const type = tar.toString("ascii", off + 156, off + 157);
    if (type === "0" || type === "\0") return tar.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512; // skip pax/dir headers
  }
  throw new Error(`no regular file in archive for ${path}`);
}

// Keep fixtures reviewable: cap every array, keep the shape.
function trim(value: unknown, max = 15): unknown {
  if (Array.isArray(value)) return value.slice(0, max).map((v) => trim(v, max));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, trim(v, max)]));
  }
  return value;
}

function scrub(text: string): string {
  const secrets = [process.env.GITHUB_TOKEN, process.env.SONAR_TOKEN, process.env.SONAR_API_TOKEN, process.env.SONAR_ADMIN_PASSWORD];
  for (const s of secrets) if (s) text = text.split(s).join("***");
  return text;
}

async function saveFixture(tool: string, data: unknown, count: number, result: Pick<RunResult, "exitCode" | "seconds">) {
  await mkdir("test/fixtures", { recursive: true });
  await writeFile(`test/fixtures/${tool}.json`, scrub(JSON.stringify(trim(data), null, 2)) + "\n");
  console.log(`[${tool}] exit=${result.exitCode} time=${result.seconds}s findings=${count} -> test/fixtures/${tool}.json`);
}

function fail(tool: string, r: RunResult): never {
  console.error(scrub(r.logs.slice(-3000)));
  throw new Error(`[${tool}] exit=${r.exitCode} after ${r.seconds}s, no report`);
}

// ---------- tools ----------

async function zap() {
  // The image has no /zap/wrk, so a fresh volume there is root-owned and the zap user
  // can't write. A tmpfs with uid= works for writing but empties when the container
  // stops, before the report can be copied out. So: chown a disk volume first.
  // ponytail: one extra short-lived container per ZAP job; T7 runner should own this step.
  const wrk = `ws-spike-zapwrk-${Date.now()}`;
  let r: RunResult;
  try {
    const init = await run("zap-init", {
      image: IMAGES.zap, user: "0", entrypoint: ["chown", "zap:zap", "/zap/wrk"], cmd: [],
      binds: [`${wrk}:/zap/wrk`], timeoutMs: 60_000,
    });
    if (init.exitCode !== 0) fail("zap-init", init);
    // Baseline = spider + passive rules only. Exit: 0 pass, 1 FAIL rules, 2 WARN rules, 3 error.
    r = await run("zap", {
      image: IMAGES.zap,
      cmd: ["zap-baseline.py", "-t", DAST_TARGET, "-J", "report.json", "-m", "2"],
      binds: [`${wrk}:/zap/wrk`],
      readFile: "/zap/wrk/report.json",
      timeoutMs: 15 * 60_000,
    });
  } finally {
    await docker.getVolume(wrk).remove().catch(() => {});
  }
  if (!r.file || r.exitCode > 2) fail("zap", r);
  const report = JSON.parse(r.file.toString("utf8"));
  const count = report.site.reduce((n: number, s: { alerts: unknown[] }) => n + s.alerts.length, 0);
  await saveFixture("zap", report, count, r);
}

async function wapiti() {
  const r = await run("wapiti", {
    image: IMAGES.wapiti,
    // SPAs expose few crawlable links: seed a URL with a parameter so attack modules have input.
    cmd: ["--url", `${DAST_TARGET}/`, "--start", `${DAST_TARGET}/rest/products/search?q=apple`,
      "-f", "json", "-o", "/out/report.json", "--flush-session",
      "--max-scan-time", "300", "--max-attack-time", "60"],
    mountAt: "/out",
    readFile: "/out/report.json",
    timeoutMs: 10 * 60_000,
  });
  if (!r.file) fail("wapiti", r);
  const report = JSON.parse(r.file.toString("utf8"));
  const count = Object.values(report.vulnerabilities as Record<string, unknown[]>).reduce((n, v) => n + v.length, 0);
  await saveFixture("wapiti", report, count, r);
}

async function trivyRun(repo: string, env: string[] = []) {
  return run("trivy", {
    image: IMAGES.trivy,
    cmd: ["repo", "--format", "json", "--output", "/out/report.json", "--scanners", "vuln,secret,misconfig", "--", repo],
    env,
    mountAt: "/out",
    binds: ["webscan-trivy-cache:/root/.cache/trivy"], // vuln DB survives between runs
    readFile: "/out/report.json",
    timeoutMs: 10 * 60_000,
  });
}

function countTrivy(report: { Results?: Array<Record<string, unknown[] | undefined>> }): number {
  return (report.Results ?? []).reduce(
    (n, r) => n + (r.Vulnerabilities?.length ?? 0) + (r.Secrets?.length ?? 0) + (r.Misconfigurations?.length ?? 0), 0);
}

async function trivy() {
  const r = await trivyRun(SAST_REPO);
  if (!r.file || r.exitCode !== 0) fail("trivy", r);
  const report = JSON.parse(r.file.toString("utf8"));
  await saveFixture("trivy", report, countTrivy(report), r);
}

async function trivyPrivate() {
  const repo = process.env.SPIKE_PRIVATE_REPO;
  if (!repo || !process.env.GITHUB_TOKEN) {
    console.log("[trivy-private] skipped: set SPIKE_PRIVATE_REPO and GITHUB_TOKEN in .env");
    return;
  }
  const r = await trivyRun(repo, [`GITHUB_TOKEN=${process.env.GITHUB_TOKEN}`]);
  if (!r.file || r.exitCode !== 0) fail("trivy-private", r);
  const report = JSON.parse(r.file.toString("utf8"));
  console.log(`[trivy-private] exit=${r.exitCode} time=${r.seconds}s findings=${countTrivy(report)} (no fixture saved)`);
}

// ---------- SonarQube ----------

async function sonarApi(path: string, init: RequestInit & { auth?: string } = {}) {
  const res = await fetch(`${SONAR_HOST}${path}`, {
    ...init,
    headers: { Authorization: init.auth ?? `Bearer ${process.env.SONAR_API_TOKEN}`, ...init.headers },
  });
  if (!res.ok) throw new Error(`SonarQube ${init.method ?? "GET"} ${path} -> ${res.status} ${await res.text()}`);
  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

async function waitForSonar() {
  for (let i = 0; i < 60; i++) {
    const status = await fetch(`${SONAR_HOST}/api/system/status`).then((r) => r.json()).catch(() => null);
    if (status?.status === "UP") return;
    await new Promise((r) => setTimeout(r, 5000));
  }
  throw new Error("SonarQube not UP after 5 min (docker compose --profile sonar up -d sonarqube)");
}

// First run only: rotate the default admin password and mint two tokens into .env.
async function ensureSonarTokens() {
  if (process.env.SONAR_TOKEN && process.env.SONAR_API_TOKEN) return;
  const basic = (pw: string) => `Basic ${Buffer.from(`admin:${pw}`).toString("base64")}`;
  const password = `${randomBytes(18).toString("base64url")}Aa1!`;
  const form = (o: Record<string, string>) => ({ method: "POST", body: new URLSearchParams(o) });
  await sonarApi("/api/users/change_password", {
    ...form({ login: "admin", previousPassword: "admin", password }), auth: basic("admin"),
  });
  const analysis = await sonarApi("/api/user_tokens/generate", {
    ...form({ name: "webscan-analysis", type: "GLOBAL_ANALYSIS_TOKEN" }), auth: basic(password),
  });
  const api = await sonarApi("/api/user_tokens/generate", {
    ...form({ name: "webscan-api", type: "USER_TOKEN" }), auth: basic(password),
  });
  Object.assign(process.env, { SONAR_ADMIN_PASSWORD: password, SONAR_TOKEN: analysis.token, SONAR_API_TOKEN: api.token });
  await appendFile(".env", `\nSONAR_ADMIN_PASSWORD=${password}\nSONAR_TOKEN=${analysis.token}\nSONAR_API_TOKEN=${api.token}\n`);
  console.log("[sonarqube] admin password rotated; SONAR_TOKEN / SONAR_API_TOKEN written to .env");
}

async function fetchAll(path: string, key: "issues" | "hotspots") {
  const items: unknown[] = [];
  for (let page = 1; ; page++) {
    const body = await sonarApi(`${path}&ps=500&p=${page}`);
    items.push(...body[key]);
    if (items.length >= body.paging.total || body[key].length === 0) return items;
  }
}

async function sonarqube() {
  await waitForSonar();
  await ensureSonarTokens();
  const deleteProject = () =>
    sonarApi("/api/projects/delete", { method: "POST", body: new URLSearchParams({ project: PROJECT_KEY }) }).catch(() => {});
  await deleteProject();

  const source = `ws-spike-src-${Date.now()}`;
  const started = Date.now();
  try {
    const clone = await run("git", {
      image: IMAGES.git,
      cmd: ["clone", "--depth", "1", "--", SAST_REPO, "/src/repo"],
      binds: [`${source}:/src`],
      timeoutMs: 5 * 60_000,
    });
    if (clone.exitCode !== 0) fail("git", clone);

    // Source mounted read-only: the scanner's work dir lives in /tmp, so no write access is needed.
    const scan = await run("scanner", {
      image: IMAGES.scanner,
      cmd: [`-Dsonar.projectKey=${PROJECT_KEY}`, "-Dsonar.projectBaseDir=/src/repo", "-Dsonar.sources=.",
        "-Dsonar.working.directory=/tmp/scannerwork", "-Dsonar.scm.disabled=true"],
      env: [`SONAR_HOST_URL=${SONAR_IN_NET}`, `SONAR_TOKEN=${process.env.SONAR_TOKEN}`],
      binds: [`${source}:/src:ro`],
      readFile: "/tmp/scannerwork/report-task.txt",
      timeoutMs: 15 * 60_000,
    });
    if (scan.exitCode !== 0 || !scan.file) fail("scanner", scan);
    const ceTaskId = /ceTaskId=(\S+)/.exec(scan.file.toString("utf8"))?.[1];
    if (!ceTaskId) throw new Error("report-task.txt has no ceTaskId");

    let task: { status: string; errorMessage?: string };
    do {
      await new Promise((r) => setTimeout(r, 3000));
      ({ task } = await sonarApi(`/api/ce/task?id=${ceTaskId}`));
    } while (task.status === "PENDING" || task.status === "IN_PROGRESS");
    if (task.status !== "SUCCESS") throw new Error(`CE task ${task.status}: ${task.errorMessage ?? ""}`);

    const issues = await fetchAll(`/api/issues/search?components=${PROJECT_KEY}`, "issues");
    const hotspots = await fetchAll(`/api/hotspots/search?project=${PROJECT_KEY}`, "hotspots");
    const seconds = Math.round((Date.now() - started) / 1000);
    await saveFixture("sonarqube", { ceTask: task, issues, hotspots }, issues.length + hotspots.length,
      { exitCode: scan.exitCode, seconds });
  } finally {
    await deleteProject();
    await docker.getVolume(source).remove().catch(() => {});
  }
}

// ---------- main ----------

const tools: Record<string, () => Promise<void>> = { zap, wapiti, trivy, sonarqube, "trivy-private": trivyPrivate };
const selected = process.argv.slice(2).length ? process.argv.slice(2) : ["zap", "wapiti", "trivy", "sonarqube"];
let failed = false;
for (const name of selected) {
  const tool = tools[name];
  if (!tool) throw new Error(`unknown tool ${name}; choose from ${Object.keys(tools).join(", ")}`);
  try {
    await tool();
  } catch (err) {
    failed = true;
    console.error(scrub(String(err instanceof Error ? err.stack : err)));
  }
}
process.exit(failed ? 1 : 0);
