# Kế hoạch: VulnShop — target kiểm thử có ground truth chính xác

> **Trạng thái:** kế hoạch thiết kế. Phần schema (`manifest.py`, `scorer.py`) đã xong ở commit
> `157e692`. App, file đáp án, script kiểm chứng và test **chưa được viết**. Tài liệu này chỉ mô tả
> thiết kế ở mức endpoint/hành vi, không chứa payload khai thác.

## 1. Mục đích và nguyên tắc

VulnShop là web app giả lập **cố ý có lỗ hổng**, chạy trên máy cục bộ, dùng để:

1. Đo SafetyWebbing theo `benchmark/PROTOCOL.md` trên một target có **số lỗ hổng chính xác và biết trước**
   (ground truth), bổ sung cho Juice Shop (một tập con có chọn lọc) và DVWA.
2. Luyện code review: mã nguồn trông như code bình thường, không có comment hay tên gọi tiết lộ lỗi.

Con số cốt lõi: **14 lỗ hổng (13 tính điểm + 1 `out_of_capability`), 8 điều khiển an toàn
(`expect = "safe"`), N điểm `accepted_weakness`.** Ngoài 14 mục này, app không được có lỗ hổng nào khác ở
mức khai thác được.

## 2. Ràng buộc an toàn (ưu tiên cao hơn mọi mục khác)

| # | Ràng buộc | Cách thực thi |
|---|---|---|
| A1 | Chỉ bind `127.0.0.1` | `HOST` ngoài `{127.0.0.1, localhost}` thì app thoát với lỗi. Không có cờ tắt. Địa chỉ bind là hằng số sau khi kiểm tra |
| A2 | Không dữ liệu thật | User, mật khẩu, "secret" đều là dữ liệu giả sinh cố định trong script seed |
| A3 | Path traversal chỉ đọc được trong `data/sandbox/` | Đường dẫn được chuẩn hoá trên **cây ảo** rồi ánh xạ vào thư mục sandbox (xem 5.1). Có file mồi `data/sandbox/secret/decoy-passwd.txt` và `data/sandbox/etc/passwd`. Không có đường nào tới file hệ thống thật |
| A4 | SSRF chỉ gọi được loopback | Allowlist cứng `127.0.0.1`/`localhost`, mọi cổng; nối bằng `http.client` thẳng tới `127.0.0.1`; không theo redirect; giới hạn kích thước/thời gian. Đích chính là "internal service" giả ở `PORT+1` do app tự mở |
| A5 | Không OS command injection / RCE | Không gọi shell, không `eval`/`exec`, không `subprocess` |
| A6 | Không mạng ra ngoài, không API key | Chỉ `sqlite3`, `http.client` tới loopback |
| A7 | Chỉ ghi trong `testbed/vulnshop/` | DB, `oracle.jsonl`, khoá token đều nằm trong `testbed/vulnshop/data/` (git-ignore) |
| A8 | Truy vấn lỗi dùng kết nối **chỉ đọc** | Các truy vấn nối chuỗi chạy trên kết nối `mode=ro`, nên lỗi SQL không thể sửa dữ liệu |
| A9 | Chống DNS rebinding | Từ chối request có `Host` khác `127.0.0.1`/`localhost` |
| A10 | Cảnh báo | Trang chủ và README ghi "ứng dụng cố ý có lỗ hổng, không deploy" |

Hệ quả cần ghi nhận: SSRF "mọi cổng loopback" nghĩa là endpoint có thể chạm tới **các dịch vụ khác đang
nghe trên loopback của máy chạy** (ví dụ UI SafetyWebbing). Đây là yêu cầu của đề bài; README phải nói rõ và
nên chạy VulnShop trên máy không có dịch vụ nhạy cảm trên loopback.

## 3. Stack và cấu trúc thư mục

Python 3 + Flask + SQLite. Dependency duy nhất: `flask` (Werkzeug đi kèm, dùng cho băm mật khẩu của
điều khiển an toàn). Token ký bằng HMAC tự viết, không cần PyJWT.

```
testbed/vulnshop/
├── README.md                 cách chạy, bảng thước đo ngắn, cảnh báo an toàn
├── Dockerfile                tuỳ chọn; chỉ publish 127.0.0.1
├── requirements.txt          flask
├── reset.py                  CLI dựng lại DB (KHÔNG có endpoint HTTP reset)
├── verify_ground_truth.py    PoC cho V01–V13, kiểm chứng S01–S08, đối chiếu đáp án
├── vulnshop/
│   ├── __main__.py           python -m vulnshop (cổng mặc định 5050)
│   ├── config.py             đường dẫn, kiểm tra loopback
│   ├── store.py              schema + seed cố định + kết nối rw/ro
│   ├── app.py                toàn bộ route (v1 và v2) — "1 file app"
│   ├── internal.py           internal service giả ở PORT+1
│   ├── telemetry.py          ghi oracle.jsonl (xem mục 6)
│   ├── templates/            index, search, product (autoescape bật)
│   └── static/app.js         form đăng nhập/bình luận tối thiểu
└── data/                     sinh bởi reset.py, git-ignore
    ├── shop.sqlite3
    ├── oracle.jsonl          ngoài sandbox, không đọc được qua HTTP
    ├── token.key             khoá ký ngẫu nhiên mỗi lần reset
    └── sandbox/{files,secret,etc}/...
benchmark/targets/vulnshop.toml    đáp án (xem mục 7)
tests/test_benchmark_vulnshop.py   test đáp án + (tuỳ chọn) test app bằng test client
```

`python -m vulnshop` tự gọi dựng DB nếu `data/` chưa có; `reset.py` luôn dựng lại từ đầu.

## 4. Danh sách lỗ hổng: đúng 14 mục

| ID | Lỗ hổng | CWE | OWASP 2021 | Endpoint / tham số | scan_type | Mức |
|---|---|---|---|---|---|---|
| V01 | SQLi: bypass đăng nhập (nối chuỗi SQL) | CWE-89 | A03 | `POST /login`, `username` | sqli | critical |
| V02 | SQLi UNION trong tìm kiếm (lộ bảng users) | CWE-89 | A03 | `GET /api/search`, `q` | sqli | critical |
| V03 | Reflected XSS | CWE-79 | A03 | `GET /search`, `q` | xss | high |
| V04 | Stored XSS (bình luận không escape) | CWE-79 | A03 | `POST /api/comments` `body` → `GET /product/<id>` | xss | high |
| V05 | IDOR: xem đơn hàng của user khác | CWE-639 | A01 | `GET /api/orders/<id>` | auth | high |
| V06 | Thiếu kiểm tra quyền: user thường gọi API admin | CWE-862 | A01 | `GET /api/admin/users` | auth | high |
| V07 | Mass assignment: tự nâng `role` | CWE-915 | A04 | `PUT /api/profile`, `role` | auth | high |
| V08 | Token chấp nhận `alg=none` | CWE-347 | A02 | header `Authorization` trên các API v1 | auth | critical |
| V09 | Path traversal (trong sandbox) | CWE-22 | A01 | `GET /download`, `file` | general | high |
| V10 | SSRF (chỉ loopback) | CWE-918 | A10 | `GET /api/fetch`, `url` | general | high |
| V11 | Open redirect | CWE-601 | A01 | `GET /redirect`, `next` | general | medium |
| V12 | Tài khoản mặc định `admin` | CWE-798 | A07 | `POST /login` | auth | high |
| V13 | Lộ stack trace khi lỗi | CWE-209 | A05 | `GET /api/products/<id>` với id không hợp lệ | general | low |
| V14 | Băm mật khẩu MD5 không salt | CWE-328 | A02 | code đăng ký/đăng nhập (không thấy qua HTTP) | general | medium, `out_of_capability` |

Mỗi lỗ hổng nằm ở **đúng một** điểm nêu trên. Mọi chỗ khác dùng truy vấn tham số hoá, template autoescape,
kiểm tra quyền phía server.

## 5. Tám điều khiển an toàn (bản sinh đôi đã vá)

| ID | Endpoint | Cách vá | Đối ứng |
|---|---|---|---|
| S01 | `GET /api/v2/search?q=` | truy vấn tham số hoá | V02 |
| S02 | `GET /v2/search?q=` | escape HTML | V03 |
| S03 | `POST /api/v2/comments` | escape khi hiển thị | V04 |
| S04 | `GET /api/v2/orders/<id>` | kiểm tra chủ sở hữu | V05 |
| S05 | `GET /api/v2/admin/users` | kiểm tra `role=admin` từ DB | V06 |
| S06 | `GET /v2/download?file=` | đường dẫn đã chuẩn hoá phải nằm trong thư mục cho phép | V09 |
| S07 | `GET /v2/redirect?next=` | allowlist đường dẫn nội bộ | V11 |
| S08 | `POST /v2/login` | truy vấn tham số hoá + so khớp hash scrypt | V01 |

### Quyết định thiết kế để các điều khiển thật sự "an toàn"

- **Token ở API v2 xác thực nghiêm ngặt** (chỉ HS256, kiểm tra chữ ký). Nếu v2 cũng nhận `alg=none` thì
  S04/S05 bị vượt qua bằng chữ ký giả (hệ quả của V08), làm "điều khiển an toàn" thành sai. V08 vì vậy
  chỉ áp dụng cho API v1; đáp án ghi rõ điều này.
- **S08 dùng kho thông tin xác thực riêng** (`credentials`, hash scrypt, mật khẩu khác với `users.password`).
  Nếu không, `admin`/mật khẩu mặc định của V12 cũng đăng nhập được ở `/v2/login`, và điều khiển an toàn bị
  coi là có lỗi.
- **Hash mạnh dùng scrypt của Werkzeug** thay vì bcrypt/argon2: cùng loại KDF chậm có salt, không thêm
  dependency. Đây là điểm lệch so với đề bài, cần người dùng xác nhận.
- Mật khẩu seed của user không phải admin đủ mạnh, để việc bẻ MD5 sau khi lộ hash (V02) không tạo thêm
  đường tấn công ngoài danh sách.
- Chuỗi V07 → S05 là hợp lệ: user đã tự nâng `role` thì qua được S05. Đó là hệ quả của V07, không phải lỗi
  của S05. Script kiểm chứng dùng user chưa bị nâng quyền cho S05.

### 5.1 Sandbox cho V09 và S06

Đường dẫn ảo gốc `/var/www/files` được ghép với tham số `file`, chuẩn hoá bằng `posixpath.normpath` trên
đường dẫn **tuyệt đối ảo** (nên `..` không thể vượt gốc ảo, giống chroot), rồi mới ghép vào
`data/sandbox/`. Kết quả luôn nằm trong sandbox; ngoài ra có thêm bước `realpath` phải nằm trong sandbox.
Sandbox chứa file thường (không symlink) do `reset.py` tạo. Lỗ hổng V09 là **thiếu kiểm tra đường dẫn
nằm trong thư mục `files`** (đọc được cả `etc/passwd` mồi và `secret/decoy-passwd.txt`), không phải khả
năng đọc file thật. S06 thêm đúng kiểm tra đó.

### 5.2 Internal service cho V10

Server HTTP tối giản ở `PORT+1`, chỉ bind `127.0.0.1`, trả dữ liệu giả có cờ `FLAG{V10-...}`. Nếu cổng
bận, app từ chối khởi động.

## 6. Oracle: xác nhận khai thác khách quan

- Mỗi V01–V13 có một cờ `FLAG{Vxx-<8 hex cố định>}`.
- Thành công được ghi vào `data/oracle.jsonl` (mỗi dòng: `id`, `ts`, `flag`, `request` đã rút gọn, mật khẩu
  được che). Với V09 và V10, cờ còn nằm trong chính response (file mồi, internal service).
- **Phát hiện đặt trong `telemetry.py` qua hook `after_request`, quan sát request/response**, không đặt lệnh
  ghi trong handler. Nhờ vậy khi review route thì không thấy vị trí lỗi qua lời gọi oracle.
- V08: ghi khi một request v1 mang token `alg=none` được chấp nhận.
- Chỉ `telemetry.py` được phép nhắc tới ID/cờ; phần còn lại của mã nguồn không có từ nào tiết lộ lỗ hổng.
- Ngoại lệ có chủ đích: tên gói `vulnshop` và biểu ngữ cảnh báo ở trang chủ/README, do yêu cầu A10.

### Đã làm trong `manifest.py` (commit `157e692`)

- `target` nhận thêm `"vulnshop"`.
- Oracle kind mới `file_oracle` (`key`, ví dụ `"V01"`), chỉ hợp lệ với `vulnshop`.
- `[[accepted_weakness]]` (id, title, cwe tuỳ chọn, reason bắt buộc, id không trùng).
- `scorer.py`: `file_oracle` được chấm như `juice_challenge` — key mới xuất hiện trong
  `oracle_newly_solved` thì tính là đã khai thác.
- **Còn thiếu:** runner chụp `oracle.jsonl` trước/sau mỗi trial rồi điền `oracle_newly_solved`; chưa có
  runner chính thức nên đây là việc của task runner.
- **Còn thiếu:** scorer chưa dùng `accepted_weakness` để loại finding ngoài phạm vi.

## 7. File đáp án `benchmark/targets/vulnshop.toml`

- Header: tổng 14 vulnerable, 13 scored, 1 `out_of_capability`, 8 safe, danh sách `accepted_weakness`.
- Ghi chú đầu file: "ĐÁP ÁN, phải để ngoài tầm với của agent và của người review khi test mù".
- `target = "vulnshop"`, `config = "default"`.
- 14 mục `[[vuln]]` với id dạng `vs-sqli-login`, `vs-sqli-search-union`, `vs-xss-reflected`,
  `vs-xss-stored-comment`, `vs-bac-order-idor`, `vs-bac-admin-users`, `vs-bac-mass-assignment`,
  `vs-auth-token-none`, `vs-path-traversal-download`, `vs-ssrf-fetch`, `vs-open-redirect`,
  `vs-auth-default-admin`, `vs-info-stack-trace`, `vs-crypto-md5`. Mỗi mục có `title`, `scan_type`, `cwe`,
  `endpoints`, `oracles`, `notes`. V14 có `scoring = "out_of_capability"` và không cần oracle.
- Mỗi mục V01–V13 có ít nhất một `file_oracle` **và** một `trace_match` (request/response pattern; cờ
  nằm trong response cho V09/V10).
- 8 mục `[[vuln]]` với `expect = "safe"` (S01–S08): chỉ cần `endpoints`, không oracle.
- `scan_type` hợp lệ theo `config.SCAN_TYPES`: `sqli`, `xss`, `auth`, `general`.

### `accepted_weakness` (dự kiến, mọi mục kèm lý do "chỉ chạy loopback, dữ liệu giả")

| id | Nội dung | CWE |
|---|---|---|
| `aw-no-https` | HTTP thuần | CWE-319 |
| `aw-security-headers` | thiếu CSP, X-Frame-Options, … | CWE-693 |
| `aw-no-csrf-token` | không có CSRF token (API dùng header, không cookie) | CWE-352 |
| `aw-no-rate-limit` | không giới hạn tần suất / khoá tài khoản | CWE-307 |
| `aw-server-banner` | header `Server` lộ Werkzeug/Python | CWE-200 |
| `aw-username-enumeration` | đăng ký báo trùng username | CWE-204 |
| `aw-open-registration` | đăng ký mở, không xác minh | CWE-1390 |
| `aw-seed-credentials` | mật khẩu giả cố định trong script seed | CWE-798 |

N = 8 theo dự kiến; con số cuối chốt sau bước tự kiểm toán.

## 8. Script kiểm chứng `verify_ground_truth.py`

- Chỉ gọi HTTP vào `127.0.0.1:<port>` (mặc định 5050); đọc `oracle.jsonl` cục bộ để xác nhận.
- V01–V13: mỗi mục một PoC thật; PASS khi PoC thành công **và** `oracle.jsonl` có dòng đúng ID.
- V14: kiểm tra tĩnh trong mã nguồn (nhãn `CODE-ONLY`), vì không có biểu hiện qua HTTP.
- S01–S08: mỗi mục một thử nghiệm chứng minh payload tương ứng **không** khai thác được và không sinh dòng oracle.
- In bảng PASS/FAIL, rồi kết luận "14 vulnerable (13 khai thác được qua HTTP + 1 chỉ qua code), 8 safe,
  tổng khớp đáp án". Thoát mã khác 0 nếu số liệu lệch hoặc ID trong script không khớp `vulnshop.toml`.
- Idempotent: PoC tạo user mới ngẫu nhiên khi cần; `reset.py` đưa mọi thứ về trạng thái đầu.

## 9. Kiểm thử trong repo

- `tests/test_benchmark_vulnshop.py`: tải `vulnshop.toml` bằng `load_manifest`; kiểm tra đủ 14 vulnerable
  (13 scored + 1 `out_of_capability`) + 8 safe; mọi regex trong `trace_match` compile được; mọi mục V01–V13
  có `file_oracle`; ID khớp danh sách của script kiểm chứng; số `accepted_weakness` khớp header.
- Test của `manifest.py`/`scorer.py` đã có (5 test, commit `157e692`).
- Tuỳ chọn: test app bằng Flask test client (`pytest.importorskip("flask")`), kiểm tra từ chối `HOST`
  ngoài loopback và mỗi S-control từ chối payload của đối ứng.

## 10. Tự kiểm toán trước khi kết luận "đủ 14"

1. Chạy `bandit` (và `semgrep` nếu cài được); mọi phát hiện phải rơi vào V01–V14 hoặc `accepted_weakness`.
2. Đọc lại toàn bộ mã: truy vấn tham số hoá ngoài V01/V02; autoescape ngoài V03/V04; xử lý lỗi không lộ stack
   trace ngoài V13 (SQL lỗi ở V01/V02 phải trả lỗi chung); không có endpoint nào thiếu kiểm tra quyền
   ngoài V05–V07; không ghi log mật khẩu.
3. Báo người dùng mọi điểm yếu tìm thấy ngoài danh sách, sửa, và lặp lại.
4. Chạy app thật rồi chạy `verify_ground_truth.py`; đính kèm đầu ra trong báo cáo cuối.

## 11. Kế hoạch giao việc theo commit nhỏ

| Bước | Nội dung | Kiểm chứng |
|---|---|---|
| 1 | Schema `manifest`/`scorer` cho `vulnshop` (xong, `157e692`) | `pytest tests` |
| 2 | Khung app: `config`, `store`, `reset.py`, seed, kiểm tra loopback | chạy `reset.py`, thử `HOST` sai |
| 3 | Điều khiển an toàn S01–S08 và các route đúng chuẩn (đăng ký, hồ sơ, danh sách sản phẩm) | gọi tay |
| 4 | Từng lỗ hổng V01–V13, mỗi lỗ hổng một commit, kèm hook oracle tương ứng | PoC trong script |
| 5 | `internal.py` và sandbox V09/V10 | thử đường dẫn thoát sandbox |
| 6 | `verify_ground_truth.py` | bảng PASS/FAIL |
| 7 | `vulnshop.toml` và `tests/test_benchmark_vulnshop.py` | `pytest tests` |
| 8 | README, Dockerfile, `.gitignore` | build image, publish `127.0.0.1` |
| 9 | Tự kiểm toán (mục 10) và dòng tóm tắt cuối | báo cáo |

## 12. Rủi ro và câu hỏi mở

- **Bị bộ phân loại an toàn chặn:** khi thử sinh mã app trong session, phản hồi bị chặn 3 lần liên tiếp, kể
  cả ở bước khung app. Bước 2–9 chưa thực hiện được. Cần người dùng quyết định: gửi phản hồi cho nhà cung
  cấp để gỡ chặn nhầm, hoặc tự viết app theo tài liệu này rồi nhờ bên khác làm phần đáp án/test/README.
- **Chạy SSRF mọi cổng loopback** chạm các dịch vụ khác trên máy (mục 2). Cần xác nhận người dùng chấp nhận.
- **Scrypt thay bcrypt/argon2** (mục 5).
- **`vulnshop` và biểu ngữ cảnh báo** chứa từ "lỗ hổng/vuln", ngoại lệ so với yêu cầu "không có chuỗi nào
  tiết lộ" — do chính đề bài yêu cầu cảnh báo.
- **Telemetry** là phần duy nhất nhắc tới ID/cờ; với test review mù, nên loại `telemetry.py` khỏi phần mã
  đưa cho người review.
- Chưa có runner chính thức: `oracle.jsonl` chưa được snapshot tự động (mục 6).
