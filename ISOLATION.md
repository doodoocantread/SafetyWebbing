# Cô lập container quét (container isolation)

Agent quét chạy với quyền `FULL_ACCESS` và đọc nội dung từ web đích — nội dung đó có thể chứa
prompt injection. Vì vậy container phải chịu được một agent **đã bị điều khiển**. Tài liệu này
nói rõ container chặn những gì, cách kiểm chứng, và những giới hạn còn lại.

## Những gì được áp dụng (chế độ `docker`)

| Rủi ro | Biện pháp | Nơi cài đặt |
|---|---|---|
| Agent đọc/ghi `audit.log`, `triage.json`, kết quả run khác | Chỉ mount **thư mục của run đó** (`runs/<run_id>` → `/work/runs/<run_id>`), không mount cả `runs/` | `engines/live.py` |
| Agent gọi ra internet, LAN, cloud metadata, API của chính SafetyWebbing | Firewall egress **default-deny** trong container: chỉ cho tới cổng của target trên host + host API của LLM | `agent_image*/sw-entrypoint.sh`, `config.py` |
| Agent tự gỡ firewall | Entrypoint (root) dựng luật rồi chạy agent bằng user `agent` với **mọi capability bị bỏ** + `no-new-privs` | `sw-entrypoint.sh` |
| Ăn hết RAM/CPU/process | `--memory`, `--memory-swap` (= memory, không swap), `--cpus`, `--pids-limit` | `engines/live.py` |
| Quyền thừa | `--cap-drop ALL` + chỉ thêm `NET_ADMIN SETUID SETGID SETPCAP` cho entrypoint; `no-new-privileges`; không `--privileged`, không `--network host`, không `docker.sock` | `engines/live.py` |
| Firewall lỗi mà vẫn chạy | **Fail-closed**: entrypoint thoát mã 97 và không bao giờ chạy agent nếu không dựng được luật, đầu vào sai, hoặc kiểm tra tự động cho thấy 1.1.1.1 / metadata / cổng host khác vẫn gọi được | `sw-entrypoint.sh` |

Khi nào container được phép gọi ra ngoài:

- **Target**: chỉ TCP tới `host.docker.internal` đúng cổng của target.
- **LLM**: TCP/443 tới các host trong `config.py` — `CLAUDE_OAUTH_HOSTS` cho PentestGPT,
  `LLM_PROVIDERS[...].api_hosts` cho hackingBuddy (chỉ provider đang dùng).
- **DNS**: tới các resolver trong `/etc/resolv.conf`.
- Mọi thứ khác (IPv6 gồm cả) bị từ chối.

Người vận hành server có thể thêm host bằng `SAFETYWEBBING_EXTRA_ALLOW_DOMAINS=a.example.com,b.example.com`
(chỉ nhận tên DNS thuần; giá trị sai khiến scan bị từ chối thay vì mở rộng chính sách). Request từ UI
không bao giờ đổi được danh sách này.

## Kiểm chứng

```bash
# Không cần Docker: cờ docker run, validation, script entrypoint với đầu vào xấu
uv run pytest tests/test_container_isolation.py

# Cần Docker + image đã build: chạy một "agent giả" trong đúng vị trí của agent thật,
# thử gọi host / mạng / sửa firewall / ghi ra ngoài thư mục run
docker build -t safetywebbing-agent ./agent_image
SAFETYWEBBING_ISOLATION_IMAGE=safetywebbing-agent uv run pytest tests/test_isolation_docker.py -v
```

Nên chạy test thứ hai sau mỗi lần build lại image (nhất là khi đổi phiên bản Claude Code CLI):
nếu CLI cần thêm một host mới, scan sẽ **fail-closed** thay vì tự mở mạng — thêm host đó qua
`SAFETYWEBBING_EXTRA_ALLOW_DOMAINS`.

## Giới hạn còn lại (chưa được giải quyết)

- **Allowlist là theo IP, không theo tên miền.** Host được phân giải một lần khi container khởi động.
  Một site khác nằm sau cùng địa chỉ CDN không bị phân biệt; nếu IP của API đổi giữa chừng một scan
  rất dài thì kết nối mới có thể bị từ chối.
- **DNS vẫn mở tới resolver**, nên về lý thuyết có thể rò dữ liệu nhỏ qua truy vấn DNS.
- **Agent vẫn đọc được bản sao OAuth token** được mount vào container (để CLI tự làm mới token), và
  có thể gửi nó tới các host trong allowlist. Nó không còn gửi được ra ngoài allowlist.
- **Chế độ `direct`** (`SAFETYWEBBING_ALLOW_DIRECT=1`) chạy agent như tiến trình của host, **không
  có** các biện pháp trên. Chỉ dùng trên máy dev đáng tin.
- **Chạy tay `docker run` không qua engine** (ví dụ lệnh smoke test) thì không có firewall: entrypoint
  chỉ in cảnh báo. Engine luôn bật nó.
- Thư mục của run được tạo `0777` để user 1000 trong container ghi được; chỉ chứa dữ liệu của chính
  run đó nên chấp nhận được với công cụ một người dùng.
