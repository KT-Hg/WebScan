# Web-Scan v2 — Task List

> Kế hoạch & quyết định kiến trúc: `tasks/plan.md`.
> Lệnh chuẩn: `npm test` (= `node --test "src/**/*.test.ts"`), `npm run typecheck` (= `tsc --noEmit`), `docker compose up`.
> Không có bước build — Node 24 chạy `.ts` trực tiếp (`erasableSyntaxOnly`: không enum, không parameter properties).

---

## Phase 1 — Foundation

### Task 1: Walking skeleton
**Description:** Dựng project mới ở root: Node 24 + TS (type-stripping), Express 5, đọc & validate env bằng zod (thiếu biến → thoát với thông báo rõ), Kysely + mysql2 + Migrator (migration đầu tiên rỗng), `GET /healthz` ping DB, `compose.yaml` chỉ có MySQL cho dev, GitHub Actions chạy typecheck + test.

**Acceptance criteria:**
- [x] `npm run dev` khởi động web; `GET /healthz` → `200 {"db":"ok"}`, DB tắt → `503`
- [x] Thiếu `DATABASE_URL`/`SESSION_SECRET` → process thoát mã ≠ 0 với tên biến bị thiếu
- [x] `npm run migrate:up` / `migrate:down` chạy được, có test (round-trip latest → none → latest)

**Verification:**
- [x] `npm test` (7/7) · `npm run typecheck` xanh
- [ ] CI xanh trên `main` — *chạy khi push lần đầu*
- [x] Manual: `docker compose up -d mysql && npm run dev && curl localhost:8888/healthz` → `200 {"db":"ok"}`

**Ghi chú triển khai:** Kysely 0.29 để `Migrator`/`NO_MIGRATIONS` ở `kysely/migration`. Dùng map migration tĩnh trong `src/db.ts` thay `FileMigrationProvider` (dynamic import đường dẫn `D:\…` lỗi trên Windows) — mỗi migration mới thêm 1 dòng import.

**Dependencies:** None
**Files likely touched:** `package.json`, `tsconfig.json`, `src/config.ts`, `src/db.ts`, `src/web.ts`, `src/migrations/0001_init.ts`, `compose.yaml`, `.github/workflows/ci.yml`
**Estimated scope:** M

---

### Task 2: Spike — chạy 4 tool trong container tạm, thu fixture thật
**Description:** Script tạm (`scripts/spike-tools.ts`) dùng dockerode chạy từng tool với **mảng args** vào một target lab (`bkimminich/juice-shop` cho DAST, một repo public có lỗ hổng biết trước cho SAST), lưu output JSON thật làm fixture và ghi lại chính xác image/version/lệnh/exit code. Mục đích: chứng minh A6/A8/A9 khả thi trước khi xây gì khác.

**Acceptance criteria:**
- [ ] Có `test/fixtures/{zap,wapiti,trivy,sonarqube}.json` từ lần chạy thật (đã cắt gọn, không chứa secret)
- [ ] `docs/tools.md` ghi: image + version pin, lệnh, thư mục output, ý nghĩa exit code (ZAP: 0–2 = OK, 3 = lỗi), thời gian chạy
- [ ] Xác nhận Trivy `repo` với token qua env chạy được cho repo private; Sonar auto-create project bằng analysis token

**Verification:**
- [ ] Manual: chạy `node scripts/spike-tools.ts` thấy 4 file fixture
- [ ] Không có chuỗi token nào trong fixture (`grep -r ghp_ test/fixtures` rỗng)

**Dependencies:** T1
**Files likely touched:** `scripts/spike-tools.ts`, `test/fixtures/*.json`, `docs/tools.md`, `docker/wapiti/Dockerfile`
**Estimated scope:** M

---

### Task 3: Đăng nhập thật + session + CSRF + security headers
**Description:** Bảng `users` (`email UNIQUE`, `password_hash`, `role ENUM('admin','user')`, `disabled_at`). bcrypt cost 12 (salt sinh mỗi lần hash). Session lưu MySQL (`express-mysql-session`), cookie `HttpOnly; SameSite=Strict; Secure` (prod). Middleware `requireUser`, `requireAdmin`. Middleware CSRF: method không an toàn phải có `Origin` khớp host (hoặc `Sec-Fetch-Site: same-origin`). `helmet` với CSP không có `'unsafe-inline'`. Rate-limit login. CLI `npm run user:create -- --email x --admin` để tạo admin đầu tiên. Layout EJS chung (header/nav/flash).

**Acceptance criteria:**
- [ ] Không tồn tại tài khoản mặc định; sai mật khẩu và email không tồn tại trả **cùng** thông báo + `401`
- [ ] Lần login sai thứ 6 trong 15 phút từ một IP → `429`
- [ ] POST với `Origin` khác → `403`; login thành công đổi session id (chống fixation); logout là POST

**Verification:**
- [ ] `npm test` (integration: login/logout, rate limit, CSRF, user bị disable không login được)
- [ ] Manual: header response có `Content-Security-Policy`, cookie có đủ cờ

**Dependencies:** T1
**Files likely touched:** `src/migrations/0002_users.ts`, `src/auth.ts`, `src/auth.test.ts`, `src/web.ts`, `src/views/layout.ejs`, `src/views/login.ejs`, `scripts/user-create.ts`
**Estimated scope:** M

---

### Task 4: Admin quản lý user
**Description:** Admin xem danh sách (phân trang), tạo, sửa (email/role/đặt lại mật khẩu), vô hiệu hóa user. Validate bằng zod. Không cho tự vô hiệu hóa mình hoặc admin cuối cùng.

**Acceptance criteria:**
- [ ] User thường gọi bất kỳ route `/admin/*` → `403`
- [ ] Email trùng → lỗi hiển thị trên form, không 500
- [ ] Vô hiệu hóa user → session hiện tại của họ hết hiệu lực ở request kế tiếp

**Verification:**
- [ ] `npm test` (phân quyền, validation, bảo vệ admin cuối)
- [ ] Manual: tạo user → đăng nhập bằng user đó

**Dependencies:** T3
**Files likely touched:** `src/admin.ts`, `src/admin.test.ts`, `src/views/admin/users.ejs`, `src/views/admin/user-form.ejs`
**Estimated scope:** M

### ✅ Checkpoint 1 — Foundation
- [ ] Test + typecheck + CI xanh
- [ ] Login thật, không tài khoản mặc định
- [ ] Có fixture thật của 4 tool
- [ ] **Review với người dùng trước khi tiếp tục**

---

## Phase 2 — Scan engine

### Task 5: Chính sách target
**Description:** Module thuần `src/targets/policy.ts`: `parseWebTarget(url)` (chỉ http/https, resolve DNS, chặn loopback/private/link-local/`169.254.169.254`/IPv6 tương đương trừ khi khớp `target_allowlist`), `parseRepoTarget(url)` (https, host trong `REPO_HOSTS`, path `^/[\w.-]+/[\w.-]+(\.git)?$`, không `..`). Trả về object đã chuẩn hóa hoặc lỗi có lý do. Bảng `target_allowlist` + trang admin thêm/xóa.

**Acceptance criteria:**
- [ ] Bảng test payload bị từ chối: `;`, `$(…)`, backtick, `|`, xuống dòng, `..`, đối số bắt đầu bằng `-`, `file://`, `ssh://`, `git@…`, `127.0.0.1`, `2130706433`, `[::1]`, `169.254.169.254`, `localhost`
- [ ] Host nội bộ nằm trong allowlist → được chấp nhận
- [ ] Hàm không gọi shell, không phụ thuộc Express

**Verification:**
- [ ] `npm test` (`policy.test.ts` dạng table-driven)

**Dependencies:** T1 (allowlist UI cần T4)
**Files likely touched:** `src/targets/policy.ts`, `src/targets/policy.test.ts`, `src/migrations/0003_allowlist.ts`, `src/admin.ts`, `src/views/admin/allowlist.ejs`
**Estimated scope:** M

---

### Task 6: Hàng đợi job + worker
**Description:** Bảng `scans` + `scan_jobs` (UUID, `status`, `attempt`, `error`, `heartbeat_at`, `started_at`, `finished_at`). `enqueue()`; worker `src/worker.ts` claim bằng `SELECT … FOR UPDATE SKIP LOCKED`, concurrency `WORKER_CONCURRENCY` (mặc định 2), heartbeat 10s, timeout theo tool, lúc khởi động đánh dấu job `running` có heartbeat cũ là `failed` ("worker restarted"). SIGTERM → ngừng nhận job, chờ job đang chạy tới hạn rồi đánh dấu `failed`. Dùng tool giả `noop` để test.

**Acceptance criteria:**
- [ ] 2 worker chạy song song không bao giờ claim cùng một job (test 50 job)
- [ ] Job vượt timeout → `failed` với lỗi "timeout"; job lỗi luôn có `error` khác rỗng
- [ ] Kill -9 worker rồi khởi động lại → không job nào kẹt `running`

**Verification:**
- [ ] `npm test` (integration với MySQL thật)

**Dependencies:** T1
**Files likely touched:** `src/migrations/0004_scans.ts`, `src/jobs.ts`, `src/jobs.test.ts`, `src/worker.ts`
**Estimated scope:** M

---

### Task 7: Docker runner
**Description:** `runContainer({ image, cmd: string[], env, volumes, network, timeoutMs, limits }) → { exitCode, logs }` qua dockerode. Mỗi job một named volume `ws-job-<id>`; giới hạn `Memory`, `NanoCpus`, `PidsLimit`; `CapDrop: ['ALL']`, `no-new-privileges`; timeout → kill; `finally` luôn xóa container (và volume khi được yêu cầu). Hàm `readFileFromVolume(volume, path)` để lấy report ra (giới hạn kích thước).

**Acceptance criteria:**
- [ ] Không có `exec`/`execSync`/`spawn` với shell ở bất kỳ đâu trong `src/` (test grep)
- [ ] Container timeout bị kill và xóa; exit ≠ 0 → lỗi kèm 2 KB log cuối
- [ ] Sau 20 lần chạy test, `docker ps -a` và `docker volume ls` không còn rác của test

**Verification:**
- [ ] `npm test` (integration với image `alpine`: echo, sleep→timeout, exit 3)

**Dependencies:** T1
**Files likely touched:** `src/docker.ts`, `src/docker.test.ts`
**Estimated scope:** S

---

### Task 8: Secret tạm thời cho job
**Description:** Token Git được mã hóa AES-256-GCM (`node:crypto`, key từ `SECRET_KEY`) vào `scan_jobs.secret_enc` khi enqueue; worker giải mã, truyền **chỉ qua env** container; set `secret_enc = NULL` khi job kết thúc (mọi nhánh). Hàm `redact()` thay token trong mọi log/lỗi trước khi ghi DB hoặc console.

**Acceptance criteria:**
- [ ] Sau khi job kết thúc (thành công/lỗi/timeout/hủy) `secret_enc IS NULL`
- [ ] Lỗi chứa token → chuỗi lưu DB và log có `***` thay token
- [ ] Sai key / dữ liệu bị sửa → giải mã throw, job `failed`

**Verification:**
- [ ] `npm test` (`secrets.test.ts` + test job với token giả `ghp_TESTTOKEN`)

**Dependencies:** T6, T7
**Files likely touched:** `src/secrets.ts`, `src/secrets.test.ts`, `src/worker.ts`
**Estimated scope:** S

---

### Task 9: Trivy adapter + normalizer
**Description:** Định nghĩa `Finding` (`severity: critical|high|medium|low|info`, `title`, `cwe?`, `cve?`, `location`, `description`, `solution?`, `references[]`, `fingerprint`) và interface adapter `{ containerSpec(job), normalize(raw) }`. Trivy: `trivy repo --format json --scanners vuln,secret,misconfig -o /out/report.json -- <url>`, token qua `GITHUB_TOKEN`/`GITLAB_TOKEN`, cache volume dùng chung. Bảng `findings`.

**Acceptance criteria:**
- [ ] `normalize(fixture)` trả đúng số finding và mapping severity từ fixture thật
- [ ] JSON thiếu field bắt buộc → throw lỗi rõ ràng (không trả `[]` im lặng)
- [ ] Adapter không chứa I/O — chỉ trả spec và parse

**Verification:**
- [ ] `npm test` (`tools/trivy.test.ts` với `test/fixtures/trivy.json`)

**Dependencies:** T2 (fixture). Ghép vào worker cần T7.
**Files likely touched:** `src/findings.ts`, `src/tools/trivy.ts`, `src/tools/trivy.test.ts`, `src/migrations/0005_findings.ts`
**Estimated scope:** S

---

### Task 10: Lát cắt E2E đầu tiên — Trivy từ UI
**Description:** Trang "Scan mới" (một form, một endpoint `POST /scans`, không inline JS), validate bằng T5, enqueue T6; worker chạy adapter T9 qua T7 với secret T8, lưu findings + artifact; trang `/scans/:id` hiển thị trạng thái và bảng findings. Chỉ chủ sở hữu (hoặc admin) xem được; người khác → `404`.

**Acceptance criteria:**
- [ ] Scan repo public từ UI → trạng thái `succeeded`, findings hiển thị
- [ ] Repo private + token → chạy được; token không có trong DB sau khi xong, không có trong HTML, không có trong log worker
- [ ] User B mở `/scans/<id của A>` → `404`

**Verification:**
- [ ] `npm test` (integration: submit → worker xử lý với fixture-runner giả → render)
- [ ] Manual: chạy thật với 1 repo public, 1 repo private

**Dependencies:** T3, T5, T6, T7, T8, T9
**Files likely touched:** `src/scans.ts`, `src/scans.test.ts`, `src/views/scans/new.ejs`, `src/views/scans/show.ejs`, `src/public/app.js`
**Estimated scope:** M

### ✅ Checkpoint 2 — Một tool chạy end-to-end
- [ ] Trivy public + private chạy từ UI
- [ ] Token không xuất hiện trong DB/log/HTML
- [ ] Kill worker giữa chừng → job `failed`, không kẹt
- [ ] **Review với người dùng**

---

## Phase 3 — Các tool còn lại + gộp báo cáo

### Task 11: Scan nhiều tool
**Description:** Một `scan` có N `scan_jobs` (một job mỗi tool). Trạng thái scan suy ra: còn job chạy → `running`; tất cả xong → `succeeded` nếu ≥1 job thành công (`partial` nếu có job lỗi), `failed` nếu tất cả lỗi. Form scan cho chọn ZAP/Wapiti/Both hoặc SonarQube/Trivy/Both.

**Acceptance criteria:**
- [ ] "Both" tạo đúng 2 job, cùng `scan_id` (liên kết bằng khóa ngoại, không dựa vào tên/timestamp)
- [ ] Một tool lỗi, tool kia thành công → scan `partial`, findings của tool thành công vẫn hiển thị
- [ ] Hủy scan → mọi job `queued` thành `canceled`, job `running` bị kill

**Verification:**
- [ ] `npm test` (bảng trạng thái suy ra + hủy)

**Dependencies:** T10
**Files likely touched:** `src/scans.ts`, `src/jobs.ts`, `src/scans.test.ts`, `src/views/scans/new.ejs`
**Estimated scope:** S

---

### Task 12: ZAP adapter
**Description:** `ghcr.io/zaproxy/zaproxy:<pin>`, `zap-baseline.py -t <url> -J report.json` (mặc định), `zap-full-scan.py` khi admin bật active scan. Volume job mount `/zap/wrk`. Exit 0–2 = thành công, 3 = lỗi. Normalizer: mỗi alert × instance → finding, CWE từ `cweid`, **strip HTML** khỏi `desc/solution/otherinfo` (render text escaped).

**Acceptance criteria:**
- [ ] `normalize(fixture)` đúng số finding, severity từ `riskcode`, CWE có giá trị
- [ ] Fixture chứa `<script>` trong `otherinfo` → render ra text đã escape
- [ ] Exit code 2 (có cảnh báo) → job `succeeded`

**Verification:**
- [ ] `npm test` (`tools/zap.test.ts`)
- [ ] Manual: scan Juice Shop trong compose network

**Dependencies:** T2, T7, T11
**Files likely touched:** `src/tools/zap.ts`, `src/tools/zap.test.ts`, `src/tools/index.ts`
**Estimated scope:** S

---

### Task 13: Wapiti adapter
**Description:** `docker/wapiti/Dockerfile` (python slim + `wapiti3==<pin>`, user non-root). Args: `wapiti --url <url> -f json -o /out/report.json --flush-session --max-scan-time <t>` + module list cấu hình được. Normalizer: map category Wapiti → CWE bằng bảng tĩnh nhỏ, severity từ `level`.

**Acceptance criteria:**
- [ ] `normalize(fixture)` đúng số finding, mọi category trong fixture có CWE
- [ ] Image build được trong CI, chạy non-root
- [ ] `--max-scan-time` lấy từ cấu hình timeout của tool (comment khớp giá trị thật)

**Verification:**
- [ ] `npm test` (`tools/wapiti.test.ts`) · `docker build docker/wapiti`

**Dependencies:** T2, T7, T11
**Files likely touched:** `docker/wapiti/Dockerfile`, `src/tools/wapiti.ts`, `src/tools/wapiti.test.ts`, `src/tools/index.ts`
**Estimated scope:** S

---

### Task 14: SonarQube adapter
**Description:** Bước 1: container `alpine/git` với script cố định `git -c http.extraHeader="Authorization: Basic $GIT_AUTH" clone --depth 1 -- "$1" /src` (URL là positional arg, token qua env). Bước 2: `sonarsource/sonar-scanner-cli:<pin>`, `SONAR_TOKEN` qua env, `-Dsonar.projectKey=ws-<jobId>`. Bước 3: đọc `ceTaskId` từ `.scannerwork/report-task.txt`, poll `/api/ce/task?id=` tới `SUCCESS|FAILED|CANCELED`. Bước 4: lấy `/api/issues/search` + `/api/hotspots/search` **phân trang `ps=500`**. `finally`: xóa project + volume. Dùng `fetch`.

**Acceptance criteria:**
- [ ] CE task `FAILED`/`CANCELED` → job `failed`
- [ ] Project có >500 issue → lấy đủ (test với mock fetch trả nhiều trang)
- [ ] Clone lỗi / scanner lỗi → project Sonar và volume vẫn bị xóa

**Verification:**
- [ ] `npm test` (`tools/sonarqube.test.ts`: normalize fixture, phân trang, các nhánh trạng thái CE)
- [ ] Manual: scan repo mẫu với Sonar trong compose

**Dependencies:** T2, T7, T8, T11
**Files likely touched:** `src/tools/sonarqube.ts`, `src/tools/sonarqube.test.ts`, `src/tools/index.ts`
**Estimated scope:** M

---

### Task 15: Gộp & khử trùng findings
**Description:** `fingerprint(finding)`: DAST = `cwe + host + path chuẩn hóa + param`; dependency = `cve + package`; code = `rule/cwe + file + line`. Khi lưu, finding trùng fingerprint trong cùng scan được gộp, `tools` là danh sách tool cùng phát hiện, severity lấy mức cao nhất. Thay thế hoàn toàn `mergeDASTReports`/`mergeSASTReports` cũ.

**Acceptance criteria:**
- [ ] Fixture ZAP + Wapiti cùng báo XSS ở cùng path/param → 1 finding, `tools = [zap, wapiti]`
- [ ] Hai finding khác path → không bị gộp
- [ ] Báo cáo hiển thị cột "Phát hiện bởi" và lọc được "chỉ findings ≥2 tool"

**Verification:**
- [ ] `npm test` (`findings.test.ts` table-driven)

**Dependencies:** T9, T12, T13, T14
**Files likely touched:** `src/findings.ts`, `src/findings.test.ts`, `src/views/scans/show.ejs`
**Estimated scope:** S

### ✅ Checkpoint 3 — Đủ 4 tool
- [ ] DAST Both + SAST Both E2E trên target lab
- [ ] Lỗ hổng chung hiển thị một dòng, hai tool
- [ ] **Review với người dùng**

---

## Phase 4 — Tính năng sản phẩm (parity với v1)

### Task 16: Target đã lưu + lịch sử
**Description:** Bảng `targets` (owner, name, kind, url, tools). CRUD target của mình; "Chạy" = `POST /targets/:id/scans` (form hỏi token nếu repo private — token không lưu). Lịch sử = danh sách `scans` của mình (phân trang, lọc theo trạng thái/tool), "Lưu thành target" từ một scan cũ.

**Acceptance criteria:**
- [ ] User chỉ thấy/sửa/xóa target của mình; của người khác → `404`
- [ ] Danh sách phân trang server-side (25/trang), không load toàn bộ
- [ ] Không có nút/handler nào nhúng dữ liệu người dùng vào JS inline

**Verification:**
- [ ] `npm test` (IDOR, phân trang)

**Dependencies:** T11
**Files likely touched:** `src/migrations/0006_targets.ts`, `src/targets/routes.ts`, `src/targets/routes.test.ts`, `src/views/targets/*.ejs`
**Estimated scope:** M

---

### Task 17: Trang báo cáo + xuất + xóa/hủy
**Description:** `/scans/:id`: lọc theo severity/tool, sắp xếp, phân trang server-side; tải artifact JSON gốc của từng tool (tra theo id job, không nhận đường dẫn); xuất báo cáo HTML tự chứa và JSON chuẩn hóa. Xóa scan = xóa rows (transaction) rồi xóa volume/artifact. Hủy scan đang chạy.

**Acceptance criteria:**
- [ ] Không route nào nhận tên/đường dẫn file từ người dùng
- [ ] Xóa scan → không còn artifact trên đĩa/volume
- [ ] File HTML xuất mở được offline, mọi nội dung từ tool đã escape

**Verification:**
- [ ] `npm test` (xuất, xóa, quyền tải artifact)
- [ ] Manual: mở file HTML xuất trong trình duyệt

**Dependencies:** T15
**Files likely touched:** `src/scans.ts`, `src/report.ts`, `src/report.test.ts`, `src/views/scans/show.ejs`, `src/views/report-export.ejs`
**Estimated scope:** M

---

### Task 18: Dashboard
**Description:** Trang chủ: số scan theo trạng thái, số finding theo severity (của mình; admin xem toàn hệ thống), 10 scan gần nhất. Trang có scan đang chạy tự refresh (`<meta http-equiv="refresh">` hoặc poll `/scans/:id/status` từ `app.js`).

**Acceptance criteria:**
- [ ] Số liệu khớp DB (test với dữ liệu seed)
- [ ] Trạng thái job cập nhật trên UI không cần F5 thủ công
- [ ] Query dashboard dùng aggregate SQL, không load toàn bộ findings

**Verification:**
- [ ] `npm test` · Manual: chạy 1 scan, nhìn trạng thái đổi trên dashboard

**Dependencies:** T16, T17
**Files likely touched:** `src/dashboard.ts`, `src/dashboard.test.ts`, `src/views/dashboard.ejs`, `src/public/app.js`
**Estimated scope:** S

### ✅ Checkpoint 4 — Parity với v1
- [ ] Mọi luồng trong hướng dẫn sử dụng của v1 (repo gốc) làm được trên v2

---

## Phase 5 — Triển khai & chốt

### Task 19: Compose một lệnh
**Description:** `compose.yaml`: `mysql`, `sonarqube` (profile `sonar`), `web` (không mount docker socket), `worker` (qua `tecnativa/docker-socket-proxy` chỉ bật CONTAINERS/IMAGES/VOLUMES/POST), `juice-shop` (profile `lab`). Mọi image pin version. Healthcheck + `depends_on: condition: service_healthy`. Chỉ named volume. `Dockerfile` cho app (multi-stage, non-root, `node src/web.ts` / `node src/worker.ts`). Migrations tự chạy khi `web` khởi động.

**Acceptance criteria:**
- [ ] Máy sạch: `cp .env.example .env && docker compose up -d` → web healthy, tạo admin bằng `docker compose exec web npm run user:create`
- [ ] `web` container không có `/var/run/docker.sock`
- [ ] Mọi cấu hình nằm trong `.env.example`; không cần copy ID container hay đường dẫn host

**Verification:**
- [ ] Manual trên Windows (Docker Desktop) và Linux: up → login → scan Juice Shop
- [ ] CI: `docker compose config` hợp lệ, build image app

**Dependencies:** T18
**Files likely touched:** `compose.yaml`, `Dockerfile`, `.env.example`, `.dockerignore`
**Estimated scope:** M

---

### Task 20: Bộ test bảo mật
**Description:** Bộ test end-to-end cho các lớp lỗi web phổ biến (OWASP Top 10) áp vào app, chạy trong CI. Chạy `npm audit --omit=dev` và review bằng agent `security-auditor`.

**Acceptance criteria:**
- [ ] Test cho: command injection (payload ở T5 qua `POST /scans` → `400`), path traversal khi tải artifact, XSS (finding chứa `<script>`/`');alert(1)//` render escaped), CSRF (POST khác Origin → `403`), IDOR (scan/target/artifact người khác → `404`), không có tài khoản mặc định
- [ ] `npm audit --omit=dev` không còn high/critical
- [ ] CSP không có `'unsafe-inline'`; `grep -r "<%-" src/views` chỉ còn include partial

**Verification:**
- [ ] `npm test` (`security.test.ts`) · CI xanh

**Dependencies:** T19
**Files likely touched:** `src/security.test.ts`, `.github/workflows/ci.yml`
**Estimated scope:** S

---

### Task 21: Tài liệu
**Description:** README đầy đủ (kiến trúc 1 hình, cài đặt bằng compose, tạo admin, thêm allowlist, cấu hình Sonar token, giới hạn & cảnh báo pháp lý khi scan) + hướng dẫn sử dụng cho người dùng cuối + `SECURITY.md` (cách báo lỗi bảo mật).

**Acceptance criteria:**
- [ ] Người mới làm theo README từ máy sạch tới report đầu tiên không cần hỏi thêm
- [ ] Mọi biến môi trường trong code đều có trong `.env.example` kèm giải thích
- [ ] Có `SECURITY.md` với kênh báo lỗi riêng tư

**Verification:**
- [ ] Manual: một người khác (hoặc agent session mới) làm theo README
- [ ] CI xanh

**Dependencies:** T20
**Files likely touched:** `README.md`, `docs/usage.md`, `SECURITY.md`, `.env.example`
**Estimated scope:** S

### ✅ Checkpoint — Complete
- [ ] Mọi acceptance criteria đạt
- [ ] Bộ test bảo mật T20 xanh trong CI
- [ ] `docker compose up` máy sạch → login → scan → xem report
