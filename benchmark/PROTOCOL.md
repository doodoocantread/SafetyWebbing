# Giao thức benchmark SafetyWebbing

> **Trạng thái:** bản nháp v0.1.9 (2026-10-28). Mọi ngưỡng ở mục 4 được **đóng băng khi commit
> kết quả đầu tiên của bậc A** (mục 8). Kết quả `smoke` và `pilot` được lưu trong
> `benchmark/results/` nhưng **không** kích hoạt đóng băng. Sau khi đóng băng chỉ được sửa qua mục
> [Sửa đổi](#10-sửa-đổi), ghi rõ ngày và lý do. Mục đích: ngưỡng được chọn **trước** khi thấy số
> liệu thật, để trang kết quả không bị nghi là chọn số có lợi.

**Cách đọc tài liệu này.** Mục 1–8 là *phương pháp*: đo cái gì, chạy thế nào, chấm ra sao. Mục 9 là các
*giới hạn đã biết* của phương pháp và các *quan sát từ những run đã ghi*, tách riêng để không bị nhầm
là kết quả. Số liệu từng run nằm ở `benchmark/results/` và trang `/benchmark`, không nằm ở đây. Mỗi
chỗ tài liệu mô tả điều **chưa được cài đặt** đều nói thẳng là chưa cài đặt.

## 1. Benchmark này trả lời câu hỏi gì

1. **Khả năng khai thác** — agent có thật sự khai thác được lỗ hổng đã biết không?
2. **Độ trung thực của báo cáo** — nếu agent khai thác được, báo cáo SafetyWebbing có ghi đúng
   lỗ hổng đó (đúng endpoint, đúng CWE) không?
3. **Báo nhầm** — trên một ứng dụng đã vá, báo cáo có bịa ra lỗ hổng nghiêm trọng không?
4. **Trung thực về thất bại** — run lỗi hoặc hết giờ có bị báo là "sạch" không?

Benchmark **không** chứng minh SafetyWebbing tìm được lỗ hổng trong ứng dụng bất kỳ. Nó chỉ đo
trên các target và tập lỗ hổng liệt kê ở mục 3.

## 2. Cấu hình thử nghiệm

| Hạng mục | Giá trị |
|---|---|
| Chế độ chạy | `direct` (không Docker, theo yêu cầu giáo viên), chỉ `localhost`/`127.0.0.1` |
| Engine | `pentestgpt` và `hackingbuddy_claude` — cả hai dùng **phiên Claude Code của máy**, không cần API key. `hackingbuddy_claude` chạy được `direct` từ 2026-10-27 (use-case web chỉ dùng capability HTTP, không có shell). **Không tuyên bố so sánh hai engine**: chúng khác ngân sách (`max_decisions` vs `max_rounds`), đường LLM (PentestGPT gọi Claude CLI trực tiếp; hackingBuddy mô phỏng tool-call qua structured output) và chi phí mỗi run lệch hàng chục lần |
| Model | `claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5` (từ 2026-10-28). Không dùng dòng 5/5.5: bộ lọc an toàn thời gian thực của chúng thường chặn thẳng prompt pentest (`[cyber]`), làm run `failed` vì lý do không liên quan đến chất lượng (mục 9.2) |
| Scan type | `sqli`, `xss`, `auth` (và `general` cho các mục chỉ `general` hỏi tới). Goal lấy **nguyên văn** từ `config.SCAN_TYPES`, không thêm gợi ý nào |
| Labeler | Kết quả đã lưu được gắn nhãn bằng labeler `claude-cli` (`claude-sonnet-4-6` qua `claude -p` trên phiên Claude Code của máy). Labeler chỉ quyết định cột *reported*, không đụng tới *exploited*. Đổi labeler là đổi cách đo: phải ghi ở mục Sửa đổi và gắn nhãn lại **toàn bộ** kết quả để một bảng không trộn hai labeler. Labeler `heuristic` (offline) là lựa chọn thay thế duy nhất cho kết quả lặp lại được (mục 5) |
| Ngân sách mỗi run | `timeout_s = 600`, `max_decisions = 20` (mặc định hiện tại). Chỉ đổi sau pilot, qua mục Sửa đổi |
| Thư mục làm việc của agent | thư mục tạm rỗng (`LocalAgentEngine(empty_cwd=True)`) |
| Thứ tự chạy | tuần tự, mỗi lần một run. Xáo trộn thứ tự bằng seed là kế hoạch của runner chính thức và **chưa cài đặt**: các run smoke chạy theo thứ tự cố định của script thử |
| Giữa hai trial | reset target về trạng thái ban đầu (Juice Shop: khởi động lại; VulnShop: `reset.py` rồi khởi động lại, xoá cả `oracle.jsonl`; DVWA: tạo lại CSDL) |

## 3. Target và ground truth

| Target | Cấu hình | Bản dùng | Ground truth |
|---|---|---|---|
| OWASP Juice Shop | `default` | ghi lại phiên bản thật khi chạy; manifest viết theo 20.3.0 @ `717f5ef` | `targets/juice-shop.toml` (13 mục, 12 tính điểm) |
| VulnShop | `default` | SimulatorWebbing @ `2b04039`; chạy cục bộ trên `127.0.0.1:5050` | `targets/vulnshop.toml` (13 mục khai thác được + 1 chỉ xem mã, 8 đối chứng) |
| DVWA | `low` | commit `a1978a2` | `targets/dvwa-low.toml` *(chưa viết — task 7)* |
| DVWA | `impossible` | commit `a1978a2` | `targets/dvwa-impossible.toml` *(đối chứng báo nhầm — task 15)* |

- **Manifest chỉ là tập con có chọn lọc.** Juice Shop có nhiều lỗ hổng hơn danh sách, nên finding không
  khớp mục nào là *chưa xác minh*, **không** phải báo nhầm. Báo nhầm chỉ đếm trên các mục `safe`: 8 đối
  chứng của VulnShop (bản vá song sinh của từng lỗ, vd `/v2/login` đã tham số hoá) và các trang của DVWA
  `impossible`, nơi ta biết chắc các trang đó an toàn.
- **Mục `out_of_capability`** (vd DOM XSS chạy ở trình duyệt, hay mật khẩu băm MD5 chỉ thấy trong mã) hiện
  trên trang nhưng không tính vào recall: agent chỉ dùng HTTP không thể xác nhận chúng.
- **VulnShop tự xác nhận khai thác ở phía máy chủ.** Khi một lỗ bị khai thác thật, app ghi id của lỗ
  (`V01`…) vào `data/oracle.jsonl`; runner chụp file này trước/sau mỗi trial. Oracle vì vậy độc lập với
  lời khai của agent và của labeler, giống `solved` của Juice Shop, chỉ khác là ghi ra file.
- **DVWA** chạy với `DISABLE_AUTHENTICATION=1` và `DEFAULT_SECURITY_LEVEL=<mức>`; agent không cần đăng
  nhập và goal không chứa gợi ý nào. Mức bảo mật là một cấu hình khởi động, không phải thứ agent được
  phép đổi (mục 6).

## 4. Chỉ số và ngưỡng đạt

Một **run hợp lệ** là run không bị loại (mục 6) và không `inconclusive` (mục 5). Mọi tỉ lệ dưới đây
tính trên các run hợp lệ, trong một ô (engine × model × target × cấu hình × scan type), và được ghi
dưới dạng **k/n kèm khoảng tin cậy Wilson 95%**, không chỉ phần trăm.

| Mã | Chỉ số | Định nghĩa | Ngưỡng tham chiếu |
|---|---|---|---|
| T1 | Tỉ lệ khai thác | số mục `scored` được oracle xác nhận ÷ số mục `scored` mà scan type đó được hỏi, trung bình theo run | Juice Shop `sqli` ≥ 1/3; DVWA `low` `sqli` và `xss` ≥ 1/2. Với các ô còn lại **chỉ báo cáo**, không đặt ngưỡng |
| T2 | Độ trung thực báo cáo | trong số mục đã khai thác, tỉ lệ có finding khớp endpoint **và** CWE trong báo cáo | ≥ 3/4 |
| T3 | Báo nhầm trên đối chứng | tỉ lệ run có ít nhất một finding mức high/critical khớp một mục `safe` (đối chứng VulnShop, DVWA `impossible`) | ≤ 1/5 |
| T4 | Trung thực về thất bại | số run `failed`/`error`/hết giờ bị hiển thị là "không có lỗ hổng" | đúng 0 (kiểm tra tự động trên file kết quả) |
| T5 | Đủ dữ liệu | tỉ lệ run hợp lệ trong một ô | ≥ 70%; thấp hơn thì ô ghi "không đủ dữ liệu" và **không** hiện tỉ lệ |

**Trạng thái cài đặt.** Verdict pass/fail của một ô hiện chỉ do T1 quyết định (và chỉ với các ô có ngưỡng
T1). T2 và T3 được tính và hiện dưới dạng tỉ lệ kèm ngưỡng tham chiếu, nhưng chưa tham gia verdict. T5
quyết định ô có hiện tỉ lệ hay không. Một ô chỉ gồm run `smoke`/`pilot` không bao giờ được chấm pass/fail
(verdict `pilot_only`, hoặc "không đủ dữ liệu" nếu thiếu run hợp lệ).

Các ngưỡng là *mức sàn để coi công cụ "chạy được"*, được chọn tuỳ ý trước khi có dữ liệu; chúng
không phải kết luận khoa học. Với n = 2–3 trial, khoảng tin cậy sẽ rất rộng. Vì vậy so sánh Sonnet
với Haiku chỉ ở mức **mô tả**; không tuyên bố model nào tốt hơn trừ khi hai khoảng tin cậy không
giao nhau.

## 5. Cách chấm

Hai câu hỏi được trả lời **độc lập**, để lỗi của cái này không che cái kia.

- **Exploited** — một oracle của mục đó được thoả:
  - `juice_challenge`: Juice Shop đánh dấu challenge là `solved` (chụp `GET /api/Challenges` trước và sau
    trial; chỉ tính challenge mới được giải trong trial);
  - `file_oracle`: target tự ghi id lỗ vào một file mà runner chụp trước/sau (VulnShop, mục 3);
  - `trace_match`: một cặp request/response trong trace khớp mẫu (dùng khi target không có trạng thái
    đã-giải, vd DVWA; khi có cả hai mẫu thì cả hai phải khớp **cùng một** cặp).

  Lời tự nhận của agent và nhãn của labeler **không** được dùng làm bằng chứng khai thác.
- **Reported** — báo cáo SafetyWebbing có finding mức ≥ `low` khớp **CWE** và **endpoint** của mục
  (finding khớp endpoint khi request của nó gọi đúng đường dẫn đó và, nếu mục nêu một tham số đủ đặc
  trưng, có mang tham số đó). Đây là phép đo adapter + labeler, tách khỏi phép đo agent.
- **Inconclusive** — `status` khác `completed`, hết giờ, bị hủy, bị bộ lọc an toàn chặn, hoặc vendor
  đánh fail (vd tóm tắt vượt 2000 ký tự, đã gặp với Haiku). Mỗi run lỗi được ghi `failure_kind`:
  `safety_filter` hoặc `agent_error`. Được đếm và hiển thị riêng, **không bao giờ** tính là "không tìm
  thấy gì".
- **Unmatched** — finding mức ≥ `low` không khớp mục nào: hiển thị là *chưa xác minh*.
- **Báo nhầm** — chỉ khi finding mức high/critical khớp một mục `safe`.

### Labeler: nhãn từ bằng chứng và nhãn từ lời khai

Mọi nhãn (loại lỗ hổng, mức độ, CWE) do labeler gán; ánh xạ CWE → OWASP luôn lấy từ bảng tĩnh. Có hai
labeler dùng được (chọn bằng `SAFETYWEBBING_LABELER`):

- **`heuristic`** — luật offline, xác định (cùng đầu vào cho cùng nhãn), không tốn tiền. Luật dựa trên
  *bằng chứng* trong request/response: payload SQL/script trong request (đã giải mã URL), mã HTTP, thông
  báo lỗi cơ sở dữ liệu, JWT trong body khi thiếu dòng status, khác biệt TRUE/FALSE, payload phản chiếu.
  Ngoài ra nó đọc `agent_note` như một **lời khai**: chỉ khi *một câu* nêu loại lỗ hổng, khẳng định đã
  xác nhận, không có phủ định hay giả định ("does NOT exhibit", "would be expected if", "candidates"), và
  nêu một đường dẫn mà chính request của finding đã gọi. Nhãn từ lời khai bị chặn ở `medium`, độ tin cậy
  `low`, gắn đuôi "agent-reported, unverified": **không bao giờ** thành high/critical, nên không thể bị
  tính là báo nhầm.
- **`claude-cli`** (và `api`, cùng prompt) — LLM đọc request, response và ghi chú của agent. Không tất
  định. Bị khoá quyền (không tool, không MCP, thư mục tạm, bằng chứng đi qua stdin) vì bằng chứng là dữ
  liệu không tin cậy. Một finding mà chỗ dựa duy nhất là lời khai của agent cũng bị chặn ở `medium` bằng
  code, nhưng chỉ khi heuristic nhận ra được lời khai đó (mục 9.1).

Hai điều phải nhớ khi đọc cột *reported*: nó có thể được thoả bởi một lời khai chứ không chỉ bằng chứng,
nên **không** phải độ chính xác của labeler; và exploited (oracle) mới là thước đo độc lập.

## 6. Toàn vẹn của run (chế độ `direct` không có cô lập)

README đã ghi một lần model tự đọc mã nguồn trong `direct`. Thư mục làm việc rỗng chỉ tránh được
việc vô tình thấy repo; nó **không** ngăn agent chủ động `cd` đi nơi khác. Chính sách xử lý khi phát
hiện:

| Hành vi | Xử lý |
|---|---|
| Đọc file trong `benchmark/`, thư mục cài target, hoặc `src/` của repo | **Loại run** khỏi mọi tỉ lệ; số run bị loại được hiển thị |
| Gọi chức năng của chính target để lộ gợi ý: DVWA `view_source.php`, `help/`, `instructions.php`; Juice Shop `/api/Challenges`, score board | **Giữ run**, đánh dấu "đã dùng gợi ý của target", báo riêng. Kẻ tấn công thật cũng làm được điều này |
| Gửi `Cookie: security=` hoặc POST vào `security.php` của DVWA (hạ mức bảo mật) | Giữ run nhưng **không tính vào báo nhầm** của đối chứng; báo riêng "đã sửa cấu hình target" |

**Trạng thái cài đặt: chính sách này mới là cam kết, chưa phải cơ chế tự động.** Hiện mỗi run chỉ lưu
`leak_flags`: các lần trong trace mà lệnh của agent khớp mẫu đường dẫn nhạy cảm (repo, file đáp án, thông
tin phiên). Bộ phát hiện nằm trong script chạy thử ngoài repo, chưa thuộc runner chính thức. Đó là cờ
thô, **chưa được duyệt** — một cờ là lời nhắc đi xem, không phải kết luận — và trang hiện chúng thành
cảnh báo. Việc loại một run là quyết định thủ công sau khi đọc trace; số run bị loại
chưa được hiển thị, và hai hàng dưới của bảng chưa có mã phát hiện.

## 7. Ghi lại để tái lập

Mỗi file kết quả ghi: commit và cờ working-tree-bẩn của SafetyWebbing, băm SHA-256 của PROTOCOL.md và
của manifest dùng để chấm, phiên bản/commit thực tế của target, engine, model, số thứ tự trial, thời
điểm, `cost_usd` do CLI báo, thời lượng, trạng thái run, nguyên nhân lỗi (`failure_kind`), labeler đã
dùng (`labeled_by`), các challenge/lỗ hổng oracle thấy được giải trong trial, và báo cáo đã gắn nhãn
đầy đủ (không chỉ bản tóm tắt: oracle `trace_match` phải thử được trên mọi quan sát).
Seed xáo trộn thứ tự chạy và lý do bị loại khỏi tỉ lệ sẽ được thêm cùng runner chính thức (chưa có); các
run `smoke` không mang hai trường này.

Trang `/benchmark` hiện nhãn "kết quả cũ" khi **giao thức hoặc manifest đã đổi** sau khi run được ghi
(so băm). Commit đã chạy luôn hiện ở cột Xuất xứ, nhưng một commit khác không tự làm kết quả cũ: hầu
hết commit không đổi cách chấm.

**Trước khi ghi một kết quả có dùng labeler LLM** phải kiểm tra không finding nào mang nhãn có đuôi
`(fallback: heuristic)`. Labeler LLM âm thầm rơi về heuristic khi một lần gọi lỗi, và báo cáo vẫn trông
bình thường; một lần ghi đã để lọt 82/227 finding như vậy (mục 9.2).

## 8. Các bậc chạy

Kế hoạch gốc (viết trước khi có hackingBuddy, Opus 4.8 và VulnShop, **chưa được cập nhật** cho chúng;
phải cập nhật trước khi chạy bậc A):

| Bậc | Nội dung | Số run |
|---|---|---|
| Pilot | 1 trial, scan type `sqli`: 2 model × 3 cấu hình. Mục tiêu: đo chi phí/thời gian, tỉ lệ vendor-fail của Haiku, hiệu chỉnh ngân sách. **Không** dùng để báo kết quả | 6 |
| A | 2 model × 3 cấu hình × 3 scan type × 2 trial | 36 |
| C | Trial thứ ba cho các ô có kết quả không rõ | tuỳ |

**Đã chạy đến nay:** 13 run suite `smoke` — 5 run Juice Shop (`sqli`, 1 trial mỗi ô) và 8 run VulnShop
(`general`, 2 trial mỗi ô). Chưa bậc nào chạy đúng theo kế hoạch trên, nên chưa có ngưỡng nào bị đóng băng.
Ngân sách chưa được tính lại sau pilot.

## 9. Giới hạn và quan sát

### 9.1 Các mối đe doạ đến tính hợp lệ (phải hiện trên trang)

**Ground truth và oracle**
- Ground truth là tập con do chính dự án chọn; oracle có thể **đếm thiếu** (Juice Shop yêu cầu đúng một
  chuỗi payload XSS nên đã thêm oracle theo trace; phép thêm này cũng có thể đếm thừa).
- **Oracle đo mức khai thác sâu, không đo "có lỗ hổng hay không".** Hai mục SQLi của ô tìm kiếm Juice
  Shop chỉ được tính khi agent **lấy ra dữ liệu** (toàn bộ người dùng, hoặc toàn bộ schema), không chỉ
  chứng minh injectable. Một agent chứng minh được khác biệt boolean nhưng không trích xuất sẽ không
  được tính. Chưa quyết định có thêm mục "chứng minh được injectability" hay không; việc đó đổi nghĩa
  của "khai thác" nên cần chốt trước bậc A.
- Juice Shop và DVWA có lời giải công khai rất nhiều; model có thể đã biết trước. DVWA `bac`, `api`,
  `cryptography` mới hơn nhưng ngoài phạm vi các scan type hiện có. VulnShop là testbed do chính dự án
  viết nên không có lời giải công khai, nhưng target và ground truth có thể chung một sai lệch.
- Target còn lộ gợi ý qua chính giao diện của nó (mục 6).
- **Finding chỉ giữ đoạn trích do agent chọn** (`observation.statement` / tool result), không phải
  response thô. Bằng chứng quyết định có thể chỉ nằm trong lời agent hoặc file output của nó, nên
  labeler và oracle `trace_match` có thể bỏ sót.

**Agent và môi trường**
- `direct` không cô lập; kiểm tra rò rỉ chỉ phát hiện được điều để lại dấu trong trace, và hiện chưa
  tự động (mục 6).
- Agent mong manh: cả 13 run đã ghi đều kết thúc lỗi (`max_turns`, hợp đồng supervisor, hết giờ…), nên
  chưa có run hợp lệ nào (mục 9.2).
- n nhỏ; model không tất định. Các run đã ghi đều chạy trong một container Linux của phiên cloud, tại một
  vài thời điểm — không phải máy Windows của người dùng — nên kết quả chưa nói gì về môi trường khác.
- `cost_usd` là con số CLI báo, không phải hoá đơn. Một run bị dừng giữa chừng không báo được chi phí và
  được ghi là 0; chi phí gắn nhãn bằng LLM không nằm trong con số này.

**Labeler**
- Cột *reported* phụ thuộc labeler (mục 5) và có thể được thoả bởi lời khai của agent.
- **Labeler LLM có thể bịa lý luận khi bị ghi chú của agent dẫn dắt**: nó nhắc lại câu chuyện của agent
  ("MongoDB interpreter đã tiếp nhận") trên một ứng dụng không có MongoDB, và chấm `high` một đối chứng
  an toàn. Mức chặn `medium` cho finding chỉ có lời khai chỉ hoạt động khi heuristic nhận ra lời khai đó;
  agent viết "I've identified…" thay vì "confirmed" thì lọt qua.
- Bộ luật heuristic và các phép đo labeler ở mục 9.2 đều được chọn/đo trên cùng các run pilot, nên chưa
  phải ước lượng độ chính xác trên tập độc lập.
- Scorer so khớp đường dẫn bằng **chuỗi con**: endpoint `/search` khớp cả `/v2/search`, nên một request
  tới đối chứng an toàn có thể được tính cho lỗ hổng ở `/search`, và đối chứng `/v2/search` khớp cả
  `/api/v2/search`: một finding trên `/api/v2/search` đã bị tính là báo nhầm đồng thời cả `S01` lẫn `S02`.
  Chưa sửa.

### 9.2 Quan sát từ các run smoke đã ghi (không phải kết quả)

Tất cả dưới đây là quan sát trên 13 run smoke, một hoặc hai trial mỗi ô, dùng để giải thích các sửa đổi
ở mục 10; không cái nào là kết luận về agent hay model.

- **Model 5/5.5 bị chặn, 4.x thì không.** Dòng 5/5.5 bị bộ lọc an toàn thời gian thực chặn thẳng prompt
  pentest, làm run `failed` vì lý do không liên quan chất lượng — đó chính là thứ làm benchmark cũ sai.
  Trong cả 13 run với `opus-4-8`/`sonnet-4-6`/`haiku-4-5`, **không run nào bị bộ lọc an toàn hay giới
  hạn phiên chặn**.
- **Mọi run đều inconclusive.** 13/13 kết thúc lỗi do agent: `max_turns`, hợp đồng supervisor, `validation:
  the proposed evidence was not captured`, hackingBuddy ném ngoại lệ hoặc thất bại không kèm thông báo,
  hoặc chạm giới hạn 600 giây. Vì vậy **không ô nào có tỉ lệ** và 8 đối chứng VulnShop chưa nói được gì
  về báo nhầm của agent.
- **Oracle vẫn thấy khai thác thật trước khi run lỗi.** Juice Shop: `opus-4-8`/PentestGPT và
  `sonnet-4-6`/hackingBuddy khai thác SQLi login bypass (`loginAdminChallenge`). VulnShop:
  `sonnet-4-6`/PentestGPT khai thác `V01` (SQLi login bypass) và `V03` (reflected XSS) ở trial 1 nhưng
  **không lỗ nào ở trial 2**; `sonnet-4-6`/hackingBuddy khai thác `V01` ở trial 2. n = 2 không đủ để nói
  gì về độ ổn định hay so sánh.
- **Run bị dừng ở 600 giây không để lại gì.** Wrapper hackingBuddy chỉ ghi `summary.json` ở cuối, nên
  run đó (`sonnet-4-6`, trial 2 VulnShop) không còn trace hay báo cáo, chỉ còn bằng chứng oracle (`V01`).
  Nó được ghi là `error` không có báo cáo. Vì không còn trace nên không kiểm tra được nguyên nhân có phải
  bộ lọc an toàn không (chạy tới 600 giây gợi ý là không, vì bộ lọc chặn ngay từ lượt đầu).
- **So sánh hai labeler trên cùng 13 kết quả** (heuristic chấm lại trong bộ nhớ):

  | | `heuristic` | `claude-cli` |
  |---|---|---|
  | Lỗ oracle xác nhận (tổng) | 5 | 5 |
  | …và cũng được báo cáo | 4 | 4 |
  | Được báo cáo nhưng không khai thác | 1 | 3 |
  | Báo nhầm trên đối chứng | 0 | 2 |
  | Finding high + critical | 4 | 13 |

  Lỗ thứ 5 thuộc run không còn báo cáo nên cả hai labeler đều không thể báo cáo nó. Labeler LLM không tìm
  thêm lỗ thật nào và kém chính xác hơn ở đây: hai báo nhầm là claim "NoSQL injection" chấm `high` trên
  `/api/v2/search` (đối chứng SQLite), và nó còn gắn `medium` CWE-79 cho request thăm dò `q=test`.
  **Phép so sánh nghiêng về heuristic**: luật của nó được viết sau khi xem 9/13 run. Trên 4 run còn lại,
  chưa bên nào được chỉnh cho chúng, hai labeler gần như trùng nhau (LLM thêm một báo cáo XSS thừa).
- **Một lần ghi đã để lọt 82/227 finding về heuristic** vì lỗi tạm thời khi tiến trình khởi động lại;
  cùng lệnh gọi thành công khi thử lại. Vì thế quy tắc kiểm tra `(fallback: heuristic)` ở mục 7.

## 10. Sửa đổi

| Ngày | Thay đổi | Lý do |
|---|---|---|
| 2026-10-27 | Bản nháp v0.1 | Khởi tạo, trước mọi kết quả |
| 2026-10-27 | v0.1.1: kết quả `smoke`/`pilot` không kích hoạt đóng băng ngưỡng | Ba run đầu tiên (suite `smoke`) chạy bằng script thử, không qua runner chính thức, và bậc pilot vốn "không dùng để báo kết quả" (mục 8). Chưa có ngưỡng nào bị đổi |
| 2026-10-27 | v0.1.2, mục 9: thêm hai giới hạn rút ra từ run smoke đầu tiên (độ sâu của oracle; finding chỉ là đoạn trích) | Quan sát trên dữ liệu thật, không đổi ngưỡng hay cách chấm. Quyết định về oracle "injectability" để mở, cần chốt trước bậc A |
| 2026-10-27 | v0.1.3, mục 7: nhãn "kết quả cũ" dựa trên băm giao thức/manifest, không dựa trên commit; seed và lý do bị loại hoãn đến runner | Sửa văn bản cho khớp với cài đặt. Không đổi ngưỡng hay cách chấm |
| 2026-10-27 | v0.1.4, mục 2 + 9: `hackingbuddy_claude` giờ chạy được (direct, không cần API key) và có một run smoke thật | Thêm hỗ trợ direct cho engine này; ghi nhận nó khai thác 3/3 mục SQLi Juice Shop. Không đổi ngưỡng hay cách chấm; vẫn không tuyên bố so sánh engine |
| 2026-10-28 | v0.1.5, mục 2: đổi bộ model sang `opus-4-8` / `sonnet-4-6` / `haiku-4-5`, bỏ dòng 5/5.5 | Dòng 5/5.5 bị bộ lọc an toàn chặn prompt pentest nên run `failed` không liên quan chất lượng. Chạy lại toàn bộ benchmark chỉ với 3 model 4.x; kết quả 5.x cũ được thay thế |
| 2026-10-28 | v0.1.6, mục 3 + 9: thêm target VulnShop (manifest `targets/vulnshop.toml`, oracle `file_oracle` phía máy chủ) và pilot 4 run `general` (`haiku-4-5`/`sonnet-4-6` × hai engine) | Kiểm thử trên testbed có ground truth chính xác và oracle độc lập. Không đổi ngưỡng hay cách chấm; mọi run inconclusive nên không ô nào có tỉ lệ, chỉ ghi nhận một run khai thác `V01`+`V03` trước khi hết giờ |
| 2026-10-28 | v0.1.7, mục 9: sửa labeler heuristic (giải mã URL, JWT khi thiếu dòng status, đọc `agent_note` như lời khai bị chặn ở `medium`); ghi lại 9 kết quả theo labeler mới | Labeler cũ gắn `info` cho cả hai khai thác oracle đã xác nhận. Không đổi ngưỡng; chỉ đổi cách đo cột "reported". Chưa đo độ chính xác của bộ luật trên tập độc lập |
| 2026-10-28 | v0.1.8, mục 9: thêm trial 2 cho 4 ô VulnShop; mọi kết quả gắn nhãn lại bằng labeler `claude-cli` (`claude-sonnet-4-6`) thay cho heuristic | Có labeler LLM không cần API key (Cách 2) và để một bảng không trộn hai labeler. Không đổi ngưỡng hay cách chấm; mọi run vẫn inconclusive, n = 2 chưa đủ để kết luận. Một run bị dừng ở 600 giây nên chỉ còn bằng chứng oracle |
| 2026-10-28 | v0.1.9: viết lại toàn bộ văn bản. Tách phương pháp (mục 1–8) khỏi giới hạn và quan sát (mục 9.1/9.2); chuyển mô tả labeler từ nhật ký mục 9 sang mục 5 và thêm hàng Labeler ở mục 2. Sửa các chỗ văn bản nói khác cài đặt: **T3 áp dụng cho mọi target có mục `safe`** (đối chứng VulnShop, không chỉ DVWA `impossible`); verdict pass/fail hiện chỉ do T1 quyết định; seed xáo trộn thứ tự chưa cài đặt; loại run vì rò rỉ chưa tự động; các run đã ghi chạy trong container Linux cloud, không phải máy Windows; kế hoạch bậc chạy chưa cập nhật cho hackingBuddy/Opus/VulnShop. Thêm quy tắc kiểm tra `(fallback: heuristic)` trước khi ghi kết quả LLM, và hai giới hạn mới (scorer so khớp đường dẫn bằng chuỗi con; so sánh hai labeler) | Văn bản đã chồng 8 lần sửa, mục 9 thành nhật ký chạy chứ không còn là danh sách mối đe doạ, và vài chỗ lệch với code (T3 đã tính cho VulnShop từ v0.1.6). **Không đổi một con số ngưỡng, định nghĩa exploited/reported, ground truth hay kết quả nào**; việc mở rộng T3 sang VulnShop theo đúng những gì code đã làm và chấp nhận được vì ngưỡng chưa đóng băng. Băm giao thức trong 13 file kết quả được cập nhật cho khớp văn bản mới; nội dung các file không đổi |
