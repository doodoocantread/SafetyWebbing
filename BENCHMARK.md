# SafetyWebbing — Kế hoạch Benchmark & Cải thiện

> Dự án khoa học cấp trường. Mọi target đều là **web giả lập có chủ đích (intentionally vulnerable)**,
> chạy **local (loopback)** trong Docker — khớp với whitelist ở [`config.py`](src/safetywebbing/config.py)
> (chỉ `localhost` / `127.0.0.0/8` / `::1`). Mục đích: đo chất lượng agent quét lỗ hổng một cách
> có thể lặp lại và so sánh được. Không nhắm vào hệ thống thật, không ngoài phạm vi được phép.

---

## 1. Danh sách web giả lập cho test bảo mật (vuln targets)

Chọn theo 3 tiêu chí: (a) chạy được **local qua Docker** (vì app chỉ cho target loopback), (b) có
**ground-truth** lỗ hổng công bố sẵn để chấm điểm, (c) phủ đúng 4 scan type của app (`sqli`, `xss`,
`auth`, `general`).

| # | Target | Docker | Ground-truth | sqli | xss | auth | Ghi chú |
|---|--------|--------|--------------|:---:|:---:|:---:|---------|
| 1 | **OWASP Juice Shop** | `bkimminich/juice-shop` :3000 | Scoreboard + file challenge chính thức | ✅ | ✅ | ✅ | Hiện đại (SPA/REST), đã dùng trong repo. **Target chính.** |
| 2 | **DVWA** | `vulnerables/web-dvwa` :80 | Lỗ hổng cố định theo security level (low/med/high) | ✅ | ✅ | ✅ | Kinh điển, lỗ hổng rời rạc dễ chấm từng cái. **Rất tốt cho ground-truth.** |
| 3 | **OWASP WebGoat** | `webgoat/webgoat` :8080 | Bài học có đáp án theo lesson | ⬤ | ✅ | ✅ | Tốt cho `general` + auth; cấu trúc theo lesson. |
| 4 | **bWAPP** | `raesene/bwapp` :80 | ~100 lỗ hổng phân loại sẵn | ✅ | ✅ | ✅ | Phủ rộng nhất; map sẵn sang OWASP. |
| 5 | **OWASP Mutillidae II** | `citizenstig/nowasp` :80 | Lỗ hổng theo OWASP Top 10 | ✅ | ✅ | ✅ | Có toggle security-level như DVWA. |
| 6 | **XVWA** | build/`bitnetsecdave/xvwa` :80 | Danh mục lỗ hổng theo trang | ✅ | ✅ | ⬤ | Bổ sung biến thể SQLi. |
| 7 | **VAmPI** | `erev0s/vampi` :5000 | Vuln/secure mode, BOLA/auth API | ⬤ | ⬤ | ✅ | **API REST** — phủ auth/access-control kiểu API. |
| 8 | **OWASP crAPI** | compose chính thức | Challenge list (BOLA, mass-assign…) | ⬤ | ⬤ | ✅ | API hiện đại; nặng hơn, để giai đoạn 2. |
| 9 | **Damn Vulnerable GraphQL (DVGA)** | `dolevf/dvga` :5013 | Lỗ hổng GraphQL có doc | ⬤ | ⬤ | ⬤ | Chỉ khi muốn mở rộng sang GraphQL. |

Ký hiệu: ✅ phủ tốt · ⬤ phủ một phần.

**Khuyến nghị cho benchmark v1:** Juice Shop (1) + DVWA (2) + bWAPP (4). Ba cái này cho ground-truth
rõ, cover đủ 4 scan type, và chạy Docker nhẹ.

> ⚠️ **An toàn:** các image này **cố ý có lỗ hổng** — chỉ chạy trên máy test, không expose ra mạng
> ngoài, bind vào `127.0.0.1`. Không bao giờ để chạy ở môi trường thật.

---

## 2. Thiết kế benchmark

### 2.1 Ground truth
Mỗi `(target, scan_type)` có một **danh mục lỗ hổng chuẩn** (expected findings) với: `cwe`, `owasp`,
`endpoint`/vị trí, `severity`. Nguồn:
- Juice Shop: file challenge chính thức (export JSON của scoreboard).
- DVWA: lỗ hổng cố định theo module + security level.
- bWAPP: bảng phân loại đi kèm.

Lưu dưới `benchmark/ground_truth/<target>.json` để chấm tự động.

### 2.2 Chỉ số đo (metrics)
Khớp với output thật của app (`Finding` + `Label`: `cwe`, `owasp`, `severity` trong
[`models.py`](src/safetywebbing/models.py)):

| Nhóm | Chỉ số | Ý nghĩa |
|------|--------|---------|
| Phát hiện | **Recall** (detection rate) | % lỗ hổng ground-truth mà agent tìm ra |
| Chính xác | **Precision** | % finding của agent là đúng (không false positive) |
| | **F1** | cân bằng recall/precision |
| Phân loại | **CWE accuracy** | finding đúng gán đúng CWE |
| | **OWASP accuracy** | gán đúng category (dùng bảng tĩnh `owasp.py` làm chuẩn) |
| | **Severity calibration** | lệch mức độ so với ground-truth |
| Ổn định | **Reproducibility** | độ nhất quán của finding qua N lần chạy cùng cấu hình |
| Hiệu quả | **Time / Cost** | thời gian & chi phí mỗi scan (đã có trong audit log) |
| An toàn | **Scope adherence** | agent có đi ra ngoài target/goal không (từ traces) |

### 2.3 Harness
- Chạy mỗi `(target, scan_type, model)` **N lần** (vd N=3) để đo reproducibility.
- Đọc `runs/<id>/report.json`, match finding ↔ ground-truth bằng fingerprint
  (target + CWE/loại + endpoint — đã có ở [`insights.py`](src/safetywebbing/insights.py)).
- Xuất `benchmark/results/<timestamp>.json` + bảng tổng hợp (reuse `report.py`/`overview`).
- Matching cần chuẩn hoá để tránh chấm quá chặt (đồng nghĩa CWE, endpoint tương đương).

### 2.4 Cách chạy (đề xuất CLI)
```bash
# docker compose up các target, rồi:
python -m benchmark run --targets juice-shop,dvwa,bwapp --repeat 3 --model claude-sonnet-5-5
python -m benchmark score --out benchmark/results/
```

---

## 3. Bảng task theo priority

> P0 = nền tảng benchmark (ưu tiên của đề bài). P1 = chạy & chấm điểm. P2 = cải thiện agent/app dựa
> trên kết quả. **Phần cải thiện chi tiết cần đoạn đánh giá app (chưa có) để tinh chỉnh** — xem ghi chú cuối.

| # | Task | Priority | Trạng thái | Kết quả |
|---|------|:--------:|:----------:|---------|
| 1 | `docker-compose.benchmark.yml` dựng Juice Shop + DVWA + bWAPP (bind 127.0.0.1) | **P0** | ✅ Xong | [`benchmark/docker-compose.benchmark.yml`](benchmark/docker-compose.benchmark.yml) |
| 2 | Thu thập ground-truth cho 3 target | **P0** | ✅ Xong | [`benchmark/ground_truth/*.json`](benchmark/ground_truth) |
| 3 | Schema expected-finding + matcher (fingerprint, chuẩn hoá CWE/endpoint) | **P0** | ✅ Xong | `benchmark/{spec,matcher}.py` |
| 4 | Harness `benchmark run` (lặp N lần, lưu run id) | **P0** | ✅ Xong | `benchmark/runner.py`, CLI `run` |
| 5 | `benchmark score` tính recall/precision/F1/CWE/OWASP/severity | **P1** | ✅ Xong | `benchmark/scoring.py`, CLI `score` |
| 6 | Đo reproducibility + time/cost | **P1** | ✅ Xong (từ report) | nằm trong `scoring.py` + `runner.py` |
| 7 | Scope-adherence check từ traces (agent có ra ngoài phạm vi?) | **P1** | ⬜ Chưa | Chỉ số an toàn |
| 8 | Trang/Than tab “Benchmark” trên UI hiển thị kết quả | **P1** | 5 | Trực quan hoá |
| 9 | So sánh 2 agent (PentestGPT vs hackingBuddyGPT) trên cùng benchmark | **P2** | 5 | Bảng so sánh agent |
| 10 | Mở rộng target: WebGoat + VAmPI (API) / crAPI | **P2** | 3 | Phủ API & general |
| 11 | Baseline bằng scanner truyền thống (ZAP/nuclei) để đối chiếu | **P2** | 5 | Điểm tham chiếu |
| 12 | *(từ đánh giá app)* Backlog cải thiện UX/độ tin cậy | **P2** | đánh giá app | — |

### Ghi chú về phần cải thiện từ đánh giá app
Task #12 và việc "lên plan cải thiện" chi tiết cần **đoạn đánh giá app** bạn muốn phân tích. Hiện chưa
có nội dung đó trong tin nhắn hay trong repo. Khi bạn dán vào, mình sẽ: phân tích từng điểm → map sang
task có số thứ tự + priority → chèn vào bảng trên.
