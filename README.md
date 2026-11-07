# WebScan

Nền tảng quét bảo mật ứng dụng web tự host: **DAST** (OWASP ZAP, Wapiti) cho ứng dụng đang chạy và **SAST** (SonarQube, Trivy) cho mã nguồn, gộp kết quả của các tool thành một báo cáo chung.

> 🚧 **Đang phát triển.** Đây là bản viết lại của [KT-Hg/Web-Scan](https://github.com/KT-Hg/Web-Scan). Hiện mới có phần nền (T1); xem lộ trình ở [`tasks/plan.md`](tasks/plan.md) và tiến độ từng task ở [`tasks/todo.md`](tasks/todo.md).

## Kiến trúc (mục tiêu)

- **web** (Express 5 + EJS): đăng nhập, quản lý target, xem báo cáo. Không có quyền Docker.
- **worker**: lấy job từ hàng đợi trong MySQL, chạy mỗi tool trong một container tạm (giới hạn tài nguyên, tự dọn khi xong).
- **MySQL 8**: user, target, scan, finding.
- Kết quả của mọi tool được chuẩn hóa về một model `Finding` (severity, CWE/CVE, vị trí) và gộp trùng giữa các tool.

## Chạy thử (dev)

Yêu cầu: Node.js ≥ 24.2, Docker.

```bash
cp .env.example .env
docker compose up -d mysql
npm install
npm run migrate:up
npm run dev          # http://localhost:8888/healthz
```

| Lệnh | Việc |
|---|---|
| `npm run dev` | Chạy web, tự reload khi sửa code |
| `npm test` | Chạy test (cần MySQL từ `docker compose`) |
| `npm run typecheck` | Kiểm tra kiểu TypeScript |
| `npm run migrate:up` / `migrate:down` | Áp dụng / hoàn tác migration |

Node chạy file `.ts` trực tiếp (type stripping), không có bước build.

## Lưu ý khi sử dụng

Chỉ quét hệ thống bạn sở hữu hoặc được cho phép bằng văn bản. Quét DAST gửi request tấn công thật tới target.
