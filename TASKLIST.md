# SafetyWebbing — Tasklist

Cập nhật: 2026-10-25. Gộp từ [`BENCHMARK.md`](BENCHMARK.md). Ưu tiên: **P0** nền tảng benchmark ·
**P1** chạy & đo · **P2** mở rộng/cải thiện. Trạng thái: ✅ xong · 🔄 đang làm · ⬜ chưa.

> **Hướng chạy hiện tại: KHÔNG dùng Docker.** Agent chạy ở **`direct` mode** (thẳng trên host, không
> container — *không có lớp cô lập*, nên cần opt-in rõ ràng), target chạy local không container. Nhánh
> Docker (mục A #1 + DVWA/bWAPP) để **sau**.

## A. Benchmark — nền tảng (P0)

| # | Task | P | Trạng thái | Ghi chú |
|---|------|:-:|:----------:|---------|
| 1 | Compose Docker (Juice Shop + DVWA + bWAPP) | P2 | ✅ (để sau) | `docker-compose.benchmark.yml` — chỉ dùng khi quay lại nhánh Docker |
| 2 | Ground-truth 3 target (cwe/owasp/endpoint/severity) | P0 | ✅ | `benchmark/ground_truth/*.json` |
| 3 | Schema expected-finding + matcher (chuẩn hoá CWE/endpoint, ghép 1-1) | P0 | ✅ | `spec.py`, `matcher.py` |
| 4 | Harness `run` (lặp N lần, qua `POST /api/scan`) | P0 | ✅ | `runner.py`, CLI `run` |

## B. Benchmark — chạy KHÔNG Docker (direct mode) — ưu tiên

| # | Task | P | Trạng thái | Ghi chú |
|---|------|:-:|:----------:|---------|
| 5 | `score`: recall/precision/F1/CWE/OWASP/severity/reproducibility | P1 | ✅ | `scoring.py`, CLI `score` |
| 6 | Thu time/cost mỗi scan | P1 | ✅ | trong `RunRecord` (từ report) |
| 7 | Suite chỉ Juice Shop (bỏ DVWA/bWAPP vì cần Docker) | P0 | ✅ | `benchmark/suites/juice-shop-only.json` |
| 8 | **Chạy target không-Docker**: Juice Shop qua `npm start` (hoặc `npx`) ở `:3000` | P0 | ⬜ | thay cho compose; cần Node.js |
| 9 | **Bật direct mode**: cài agent vào `.agent-venv` + `SAFETYWEBBING_ALLOW_DIRECT=1` | P0 | ⬜ | `.agent-venv` đã có sẵn — kiểm `GET /api/modes` |
| 10 | **Chạy benchmark** `--mode direct` với suite juice-shop-only, lưu baseline | P1 | ⬜ | `python -m safetywebbing.benchmark run --suite benchmark/suites/juice-shop-only.json --mode direct` |
| 11 | Scope-adherence check từ traces (agent có ra ngoài target/goal?) | P1 | ⬜ | chỉ số an toàn |
| 12 | Kiểm ground-truth đúng với bản Juice Shop đang chạy (endpoint) | P1 | ⬜ | sau khi chạy thật |

## C. Benchmark — mở rộng & trực quan (P2)

| # | Task | P | Trạng thái | Ghi chú |
|---|------|:-:|:----------:|---------|
| 13 | Tab/trang “Benchmark” trên UI hiển thị `scores.json` | P2 | ⬜ | reuse `report.py`/overview |
| 14 | So sánh 2 agent (PentestGPT vs hackingBuddyGPT) cùng suite | P2 | ⬜ | bảng so sánh |
| 15 | **Nhánh Docker**: bật lại DVWA + bWAPP (cần Docker/PHP+MySQL) + pin tag image | P2 | ⬜ | mở rộng target khi dùng Docker |
| 16 | Thêm target API: VAmPI / crAPI; GraphQL: DVGA | P2 | ⬜ | phủ auth kiểu API |
| 17 | Baseline scanner truyền thống (ZAP/nuclei) để đối chiếu | P2 | ⬜ | điểm tham chiếu |
| 18 | CWE/OWASP mở rộng cho bảng `owasp.py` (vd CWE-352 CSRF) | P2 | ⬜ | tăng owasp-accuracy |

## D. Chất lượng & chốt (P1–P2)

| # | Task | P | Trạng thái | Ghi chú |
|---|------|:-:|:----------:|---------|
| 19 | Test matcher/scoring/spec | P1 | ✅ | `tests/test_benchmark.py` (20), full 234 pass |
| 20 | README benchmark + cập nhật BENCHMARK.md | P1 | ✅ | `benchmark/README.md` |
| 21 | **Commit** toàn bộ phần benchmark | P1 | ⬜ | chưa commit |

## E. Cải thiện app — *chờ đoạn đánh giá app* (P2)

| # | Task | P | Trạng thái | Ghi chú |
|---|------|:-:|:----------:|---------|
| 22 | Phân tích đoạn đánh giá app → tách thành task có số + priority | P2 | ⬜ | **cần bạn dán đánh giá** |
| 23 | Backlog cải thiện UX/độ tin cậy từ đánh giá | P2 | ⬜ | phụ thuộc #22 |

---

**Việc nên làm tiếp (gợi ý thứ tự):** #8 chạy Juice Shop qua npm → #9 bật direct mode → #10 chạy
benchmark lấy baseline → #21 commit → #11 scope-adherence → #13 UI. Nhánh Docker (#15) và phần E
để sau. Phần E mở khoá khi có đoạn đánh giá app.
