# Scanner tools: cách chạy đã kiểm chứng (spike T2, 2026-11-07)

Mọi lệnh dưới đây chạy bằng `scripts/spike-tools.ts`: dockerode tạo container tạm, `Cmd` là **mảng tham số** (không shell), container join network `webscan-net` của `compose.yaml`, file kết quả lấy ra bằng `getArchive` sau khi container dừng, rồi xóa container + volume.

Fixture ở `test/fixtures/<tool>.json` là output thật, **mỗi mảng cắt còn ≤ 15 phần tử** (giữ nguyên cấu trúc) và đã lọc secret. Đếm trên fixture, không phải trên lần chạy đầy đủ.

```bash
docker compose --profile lab --profile sonar up -d juice-shop sonarqube
docker build -t webscan/wapiti:3.3.2 docker/wapiti
npm run spike                 # hoặc: npm run spike -- zap trivy
```

| Tool | Image (pin) | Target spike | Thời gian | Exit code | Kết quả thật |
|---|---|---|---|---|---|
| ZAP | `ghcr.io/zaproxy/zaproxy:2.17.0` | Juice Shop `v20.3.0` | ~55 s | 2 | 9 alert |
| Wapiti | `webscan/wapiti:3.3.2` (tự build) | Juice Shop | ~8 s | 0 | 4 vuln + 2 anomaly |
| Trivy | `aquasec/trivy:0.76.2` | `snyk-labs/nodejs-goof` | 30 s lạnh / 5 s có cache | 0 | 243 (241 vuln + 2 misconfig) |
| SonarQube | server `sonarqube:26.11.0.134175-community`, scanner `sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1`, clone `alpine/git:v2.54.0` | `snyk-labs/nodejs-goof` | ~30 s (clone + scan + CE) | 0 | 11 issue, 0 hotspot |

---

## ZAP

```
zap-baseline.py -t <url> -J report.json -m 2      # volume tại /zap/wrk, report: /zap/wrk/report.json
```

- **Exit code:** `0` pass · `1` có rule FAIL · `2` có rule WARN · `3` lỗi. ⇒ **0–2 là thành công**, chỉ 3 là lỗi.
- `-m 2`: spider tối đa 2 phút. Baseline chỉ chạy passive rules; active scan là `zap-full-scan.py` (cùng tham số).
- ⚠️ **Quyền ghi `/zap/wrk`:** image không có sẵn thư mục này ⇒ volume mới mount vào thuộc root ⇒ user `zap` (uid 1000) không ghi được (`AccessDeniedException`). tmpfs với `uid=1000` ghi được nhưng **bị xóa khi container dừng**, trước khi kịp copy report ra. Cách đang dùng: volume đĩa + container khởi tạo ngắn `chown zap:zap /zap/wrk` (cùng image, `User: 0`). T7 nên đưa bước này vào runner.
- Pin cũ (2.16.1) tự sinh alert **"ZAP is Out of Date" [10116]** vào report ⇒ cần cập nhật pin định kỳ, hoặc normalizer bỏ qua pluginid 10116.

**Cấu trúc** (`site[].alerts[]`): `pluginid`, `alertRef`, `alert`/`name`, `riskcode` (`0` info · `1` low · `2` medium · `3` high), `confidence`, `cweid` (chuỗi, `"-1"` = không có), `wascid`, `desc`/`solution`/`otherinfo` (**HTML** `<p>…`), `reference`, `instances[]` (`uri`, `method`, `param`, `attack`, `evidence`, `otherinfo`).
- Cùng `pluginid` có thể xuất hiện nhiều lần với `alertRef` khác nhau (vd `90004-1`, `90004-2`) ⇒ khóa là `alertRef`.
- Fixture: riskcode `{0: 3, 1: 4, 2: 2}`.

## Wapiti

```
wapiti --url <url>/ --start <url>/rest/products/search?q=apple -f json -o /out/report.json \
       --flush-session --max-scan-time 300 --max-attack-time 60
```

- Không có image chính thức ⇒ `docker/wapiti/Dockerfile` (python 3.12-slim, `wapiti3==3.3.2`, user non-root uid 10001, `/out` thuộc user đó nên volume ghi được ngay).
- **Exit code 0 kể cả khi có lỗ hổng.** Lỗi thật = exit ≠ 0 hoặc không có file report.
- ⚠️ **SPA crawl được rất ít** (Juice Shop: 9 trang). Không có `--start` với URL có tham số thì chỉ ra lỗi header. Có seed ⇒ tìm được **SQL Injection** ở `q`.

**Cấu trúc:** `vulnerabilities` / `anomalies` / `additionals` là map `{tên category: [finding]}`; finding có `method`, `path`, `info`, `level` (1–4), `parameter`, `module`, `http_request`, `curl_command`, `wstg`. `classifications` = `{category: {desc, sol, ref, wstg}}`.
- **Không có trường CWE** ⇒ T13 map category → CWE bằng bảng tĩnh.
- `http_request` / `curl_command` **chứa payload tấn công** ⇒ luôn render dạng text đã escape.
- Fixture: CSP Configuration (1) · Unencrypted Channels (2+1) · SQL Injection (4); anomalies: Internal Server Error ×2.

## Trivy

```
trivy repo --format json --output /out/report.json --scanners vuln,secret,misconfig -- <repo-url>
```

- Volume cache `webscan-trivy-cache:/root/.cache/trivy` dùng chung giữa các lần chạy (DB lỗ hổng tải lần đầu ~25 s).
- **Exit code 0 kể cả khi có lỗ hổng** (trừ khi thêm `--exit-code`).
- ⚠️ **Cần lockfile:** repo chỉ có `package.json` (vd DVNA) ⇒ 0 vuln npm. nodejs-goof có `package-lock.json` ⇒ 241 vuln.
- Repo private: biến môi trường `GITHUB_TOKEN` (GitLab: `GITLAB_TOKEN`) cho container — **chưa kiểm chứng**, xem cuối file.

**Cấu trúc** (`SchemaVersion: 2`, `Results[]`): `Target`, `Class` (`lang-pkgs` · `config` · `secret`), `Type`.
- `Vulnerabilities[]`: `VulnerabilityID` (CVE/GHSA), `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity` (`CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN`), `CweIDs[]`, `PrimaryURL`, `Title`, `Description`, `References[]`, `CVSS`.
- `Misconfigurations[]`: `ID`, `AVDID`, `Title`, `Severity`, `Message`, `Resolution`, `CauseMetadata` (dòng code).
- `Secrets[]`: (không có trong fixture).
- Fixture (đã cắt): 15 vuln `{HIGH: 10, MEDIUM: 4, CRITICAL: 1}` + 2 misconfig Dockerfile.

## SonarQube

1. **Server** (compose profile `sonar`): `SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true` vì kernel WSL của Docker Desktop có `vm.max_map_count` thấp hơn mức Elasticsearch đòi. Lên `UP` sau ~1–2 phút (`GET /api/system/status`).
2. **Lần đầu:** đổi mật khẩu `admin/admin` mặc định (`POST /api/users/change_password`), tạo 2 token rồi ghi vào `.env`:
   - `SONAR_TOKEN` = `GLOBAL_ANALYSIS_TOKEN` cho scanner — ✅ **tự tạo project khi phân tích** (project bị xóa trước mỗi lần chạy, scan vẫn thành công).
   - `SONAR_API_TOKEN` = `USER_TOKEN` (admin) cho đọc kết quả + xóa project.
3. **Clone:** `alpine/git` — `clone --depth 1 -- <url> /src/repo` vào volume riêng của job.
4. **Scan** (volume source mount **read-only**):
   ```
   -Dsonar.projectKey=ws-<jobId> -Dsonar.projectBaseDir=/src/repo -Dsonar.sources=.
   -Dsonar.working.directory=/tmp/scannerwork -Dsonar.scm.disabled=true
   ```
   env: `SONAR_HOST_URL=http://sonarqube:9000`, `SONAR_TOKEN`. Image scanner có sẵn Node 22 ⇒ phân tích được JS/TS.
5. **Chờ kết quả:** `ceTaskId` trong `/tmp/scannerwork/report-task.txt` ⇒ poll `GET /api/ce/task?id=` tới `SUCCESS | FAILED | CANCELED`.
6. **Lấy kết quả:** `GET /api/issues/search?components=<key>&ps=500&p=N` (`componentKeys` đã deprecated) và `GET /api/hotspots/search?project=<key>&ps=500&p=N`, lặp theo `paging.total`.
7. **Dọn:** `POST /api/projects/delete` + xóa volume, luôn trong `finally`.

**Cấu trúc issue:** `key`, `rule` (`javascript:S…`), `type` (`BUG|VULNERABILITY|CODE_SMELL`), `severity` (cũ: `BLOCKER|CRITICAL|MAJOR|MINOR|INFO`), `impacts[]` (`{softwareQuality, severity}`, mô hình mới), `component` (`<key>:<path>`), `line`, `textRange`, `message`, `tags` (có `cwe`, `owasp-…`).
- **CWE không nằm trong issue** ⇒ T14 lấy qua `GET /api/rules/show?key=<rule>` (securityStandards) và cache theo rule.
- Fixture: 11 issue — BUG ×6, VULNERABILITY ×5; theo file: JS 4, CSS 3, HTML 2, Dockerfile 2.
- ⚠️ **0 hotspot** trên nodejs-goof (SonarQube 2025+ chuyển một số hotspot thành issue, tag `former-hotspot`) ⇒ T14 cần một repo/fixture có hotspot để test nhánh đó.

---

## Chưa kiểm chứng

- **Trivy với repo private** (`npm run spike -- trivy-private`): cần `SPIKE_PRIVATE_REPO` + `GITHUB_TOKEN` (fine-grained, read-only, chỉ repo đó) trong `.env` — chạy trên máy của bạn, không cần chia sẻ token.
