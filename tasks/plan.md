# Implementation Plan: Web-Scan v2 (rework toàn bộ)

> v1 gốc: [KT-Hg/Web-Scan](https://github.com/KT-Hg/Web-Scan) (giữ nguyên làm mẫu). Repo này là bản viết lại, lịch sử mới.
> Task chi tiết (acceptance criteria, verification, files): `tasks/todo.md`.

## Overview

Viết lại Web-Scan thành một nền tảng quét bảo mật **an toàn khi có nhiều người dùng**: giữ nguyên ý tưởng sản phẩm (DAST bằng ZAP + Wapiti, SAST bằng SonarQube + Trivy, lưu target, lịch sử, xem/xuất báo cáo, quản trị user) với phần lõi mới:

- Đăng nhập bằng tài khoản trong DB, phân quyền theo chủ sở hữu; admin đầu tiên tạo bằng CLI.
- Mọi lệnh chạy trong **container tạm cho mỗi job**, tham số dạng mảng, không qua shell; cấu hình chỉ bằng biến môi trường.
- **Hàng đợi job** có trạng thái (`queued → running → succeeded/failed/canceled`), timeout, giới hạn đồng thời, tự phục hồi khi restart.
- **Model `Finding` chuẩn hóa** cho cả 4 tool → một template báo cáo duy nhất, gộp trùng thật sự (CWE/CVE + vị trí).
- `docker compose up` là chạy được.

## Architecture Decisions

| # | Quyết định | Lý do |
|---|---|---|
| A1 | **Node 24 LTS + TypeScript chạy thẳng bằng type-stripping** (không Babel, không bước build); `tsc --noEmit` chỉ để typecheck | Máy đã có Node 24.12. Bỏ được Babel/nodemon; type giúp các normalizer parse JSON của tool không sai field. |
| A2 | **Express 5 + EJS render server-side**, không SPA | Ít khái niệm nhất cho app CRUD + bảng báo cáo. EJS `<%= %>` auto-escape; cấm `<%-` và inline handler, có CSP. |
| A3 | **Giữ MySQL 8**, truy cập bằng **Kysely** (query builder có type + Migrator có sẵn) thay Sequelize | Giữ hạ tầng quen thuộc; Kysely luôn parameterized, migrations up/down nằm cùng chỗ. |
| A4 | **Hàng đợi job trên DB** (`SELECT … FOR UPDATE SKIP LOCKED`), không Redis | Một dependency ít hơn. `ponytail:` polling 2s, đủ cho vài chục job/giờ; chuyển BullMQ khi cần throughput. |
| A5 | **Tách 2 process: `web` và `worker`** (cùng codebase, 2 entrypoint). Chỉ `worker` có quyền Docker, qua `docker-socket-proxy` giới hạn API | Web bị lỗi ≠ chiếm host. Đây là ranh giới bảo mật quan trọng nhất. |
| A6 | **Mỗi job = container tạm qua dockerode** (`Cmd: string[]`, env cho secret, volume riêng theo job id, giới hạn RAM/CPU/PIDs, timeout → kill, luôn dọn trong `finally`) | Loại bỏ ngay từ thiết kế cả lớp lỗi command-injection và xung đột tài nguyên giữa các job chạy song song. |
| A7 | **Adapter cho mỗi tool** = `{ containerSpec(job), normalize(rawJson): Finding[] }`. Normalizer là hàm thuần, test bằng fixture JSON thật | Thêm tool mới = thêm 1 adapter; mọi báo cáo dùng chung 1 template trên `Finding`. |
| A8 | **Trivy dùng `trivy repo <url>`** (token qua env `GITHUB_TOKEN`), không tự clone | Ít bước hơn; token không đi qua URL hay command line. SonarQube vẫn cần clone: script cố định, URL là positional arg sau `--`. |
| A9 | **SonarQube**: project key `ws-<jobId>`, đọc `ceTaskId` từ `report-task.txt`, poll `/api/ce/task`, lấy issues **có phân trang**, xóa project trong `finally`; gọi bằng `fetch` built-in | Trạng thái CE chính xác (kể cả `FAILED/CANCELED`), không mất issue khi vượt 1 trang, không gọi shell. |
| A10 | **Token Git không lưu lâu dài**: lưu mã hóa AES-256-GCM chỉ trong lúc job chạy, xóa khi job kết thúc; target đã lưu **không** lưu token (hỏi lại mỗi lần chạy) | Token không tồn tại lâu dài trong DB và không bao giờ xuất hiện trong HTML/log. |
| A11 | **Chính sách target**: chỉ `http/https`; chặn IP private/loopback/link-local/metadata **trừ khi admin thêm vào allowlist**; repo chỉ từ host cho phép (`github.com`, `gitlab.com` mặc định) | Chặn SSRF/scan trái phép mà vẫn cho phép lab nội bộ (Juice Shop, DVWA…). |
| A12 | **CSRF**: cookie `SameSite=Strict` + middleware kiểm `Origin`/`Sec-Fetch-Site` cho mọi method không an toàn; mọi thao tác thay đổi dữ liệu là POST | Native, không thêm thư viện. |
| A13 | **Test bằng `node:test` built-in**; integration test chạy với MySQL + Docker thật qua compose | Không Jest. Fixture từ tool thật (task T2). |
| A14 | **Repo độc lập, lịch sử mới**; v1 ở repo gốc giữ nguyên, không sửa | Rework hoàn toàn, không strangler; v1 chỉ dùng để đối chiếu tính năng. |

### Dependencies dự kiến (runtime)
`express@5`, `ejs`, `express-session`, `express-mysql-session`, `mysql2`, `kysely`, `zod`, `bcryptjs`, `helmet`, `express-rate-limit`, `dockerode` — 11 gói. Bỏ: `axios` (dùng `fetch`), `body-parser`, `child_process`, `multer`, `moment`, `sequelize*`, `babel*`, `nodemon`.

### Schema

```
users(id, email UNIQUE, password_hash, role ENUM('admin','user'), disabled_at, created_at)
sessions(...)                                    -- express-mysql-session
target_allowlist(id, pattern, kind ENUM('host','cidr'), created_by)
targets(id, owner_id→users, name, kind ENUM('dast','sast'), url, tools JSON, created_at)
scans(id UUID, owner_id→users, target_id NULL→targets, kind, url, status, created_at, finished_at)
scan_jobs(id UUID, scan_id→scans, tool, status, attempt, error, secret_enc NULL,
          heartbeat_at, started_at, finished_at, artifact_path)
findings(id, scan_id→scans, fingerprint, tools JSON, severity ENUM, title, cwe, cve,
         location, description, solution, references JSON, INDEX(scan_id, severity))
```

### Dependency graph

```
T1 skeleton ─┬─ T2 spike tools (fixtures) ──────────────┬─ T9 Trivy adapter ─┐
             │                                           ├─ T12 ZAP adapter   │
             ├─ T3 auth ─ T4 admin users                 ├─ T13 Wapiti adapter│
             │                                           └─ T14 Sonar adapter │
             ├─ T5 target policy ─────────────┐                               │
             ├─ T6 queue+worker ─ T7 docker runner ─ T8 secrets ─────────────┤
             │                                                                ▼
             └──────────── T10 scan UI (E2E Trivy) ─ T11 multi-tool scan ─ T15 merge/dedupe
                           (T12–T14 ghép vào worker sau T11)
                                                   │
                                   T16 saved targets · T17 report+export · T18 dashboard
                                                   │
                                   T19 compose deploy ─ T20 security verification ─ T21 docs
```

## Task List

### Phase 1 — Foundation
- [x] T1: Walking skeleton (Node 24 + TS, Express 5, config, DB, migrator, healthz, CI) — *CI chạy khi push*
- [ ] T2: Spike — chạy 4 tool trong container tạm, thu fixture JSON thật **(rủi ro cao nhất, làm sớm)**
- [ ] T3: Đăng nhập thật + session + CSRF + security headers
- [ ] T4: Admin quản lý user

#### Checkpoint 1 — Foundation
- [ ] `npm test` + `npm run typecheck` xanh, CI xanh
- [ ] Login thật hoạt động; không có tài khoản mặc định
- [ ] Đã có fixture thật của cả 4 tool + ghi chú lệnh/phiên bản image
- [ ] **Review với bạn trước khi sang Phase 2**

### Phase 2 — Scan engine
- [ ] T5: Chính sách target (validate URL/repo, allowlist, chặn IP nội bộ)
- [ ] T6: Hàng đợi job + worker (claim, timeout, heartbeat, phục hồi, shutdown)
- [ ] T7: Docker runner (container tạm, giới hạn tài nguyên, dọn dẹp)
- [ ] T8: Lưu secret tạm thời (mã hóa token, xóa khi job xong, scrub log)
- [ ] T9: Trivy adapter + normalizer
- [ ] T10: Lát cắt E2E đầu tiên — form scan → job → findings trên UI (Trivy)

#### Checkpoint 2 — Một tool chạy end-to-end
- [ ] Scan repo public và private bằng Trivy từ UI, findings hiển thị
- [ ] Token không xuất hiện trong DB (sau khi xong), log, HTML
- [ ] Kill worker giữa chừng → job thành `failed`, không kẹt `running`
- [ ] **Review với bạn**

### Phase 3 — Các tool còn lại + gộp báo cáo
- [ ] T11: Model scan nhiều tool (DAST = ZAP+Wapiti, SAST = Sonar+Trivy) — trạng thái scan suy ra từ các job
- [ ] T12: ZAP adapter + normalizer
- [ ] T13: Wapiti adapter (image tự build, pin version) + normalizer
- [ ] T14: SonarQube adapter (clone an toàn, ceTask, phân trang, dọn project)
- [ ] T15: Gộp & khử trùng findings (fingerprint) giữa các tool

#### Checkpoint 3 — Đủ 4 tool
- [ ] DAST "Both" và SAST "Both" chạy E2E trên target lab (Juice Shop / repo mẫu)
- [ ] Một lỗ hổng mà 2 tool cùng báo hiển thị **một** dòng với 2 tool
- [ ] **Review với bạn**

### Phase 4 — Tính năng sản phẩm
- [ ] T16: Target đã lưu (thay ScanRequest) + lịch sử scan (thay ScanRequestHistory)
- [ ] T17: Trang báo cáo (lọc/sắp xếp/phân trang server-side) + xuất JSON/HTML + xóa/hủy scan
- [ ] T18: Dashboard (thống kê, scan gần đây, tự refresh khi đang chạy)

#### Checkpoint 4 — Feature parity với v1
- [ ] Mọi luồng trong hướng dẫn sử dụng của v1 (repo gốc) làm được trên v2

### Phase 5 — Triển khai & chốt
- [ ] T19: `compose.yaml` một lệnh (mysql, sonarqube, web, worker, socket-proxy), image pin version, healthcheck
- [ ] T20: Bộ test bảo mật (injection, traversal, XSS, CSRF, IDOR, `npm audit`)
- [ ] T21: README đầy đủ + hướng dẫn sử dụng

#### Checkpoint — Complete
- [ ] Mọi acceptance criteria đạt; bộ test bảo mật T20 xanh trong CI
- [ ] `docker compose up` trên máy sạch → login → scan → xem report

## Parallelization

- Sau **T2** (có fixture): các normalizer của T9/T12/T13/T14 là hàm thuần, độc lập file → làm song song với T3–T8.
- **T3–T4** (auth) và **T5–T8** (engine) không đụng file của nhau → 2 luồng song song sau T1.
- Phải tuần tự: migrations (T1→T3→T6→T11→T15→T16), T10 cần T6–T9.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Worker có quyền Docker = root trên host | High | Chỉ worker có quyền, qua `docker-socket-proxy` (chỉ CONTAINERS/IMAGES/VOLUMES); web không bao giờ mount socket; khuyến nghị chạy trên VM riêng. |
| Quét DAST site của bên thứ ba là hành vi trái phép | High | Chặn IP nội bộ + allowlist do admin quản lý (A11); log ai scan gì; ZAP mặc định **baseline (passive)**, active scan là tùy chọn admin bật. |
| Định dạng JSON của tool đổi theo version | Med | Pin version image; normalizer test bằng fixture; test fail khi field biến mất thay vì im lặng. |
| SonarQube nặng (≥2 GB RAM, `vm.max_map_count` trên Linux) | Med | Compose profile `sonar` tùy chọn; SAST vẫn chạy được chỉ với Trivy. |
| Trivy DB cache dùng chung bị lock khi chạy song song | Med | Volume cache dùng chung + giới hạn đồng thời theo tool (mặc định Trivy = 1). |
| Docker Desktop trên Windows: bind mount đường dẫn host khác Linux | Med | Chỉ dùng **named volume**, không bind mount đường dẫn host. |
| ZAP full scan chạy hàng giờ | Med | Timeout theo tool (env), mặc định ZAP baseline 15 phút; hủy được từ UI. |
| Scope creep khi rework | Med | Phase 4 chỉ đạt parity với v1; tính năng mới (lịch quét, SARIF, webhook CI) để sau Checkpoint Complete. |

## Decisions (chốt 2026-11-07)

1. **Stack:** TypeScript + EJS server-render (không SPA).
2. **DB:** MySQL 8.
3. **Phạm vi target DAST:** chặn IP nội bộ, mở bằng allowlist do admin quản lý.
4. **Token Git cho target đã lưu:** không lưu, hỏi lại mỗi lần chạy.
5. **ZAP:** baseline/passive mặc định; active scan do admin bật.
6. **Dữ liệu v1:** không migrate.

## Open Questions

7. **Ngôn ngữ giao diện:** tiếng Việt hay tiếng Anh? (cần chốt trước T3 — trang login đầu tiên)
