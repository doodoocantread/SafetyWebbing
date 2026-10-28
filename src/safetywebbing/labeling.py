"""Labeler: the NARRATIVE layer (ARCHITECTURE.md §6).

Takes fact-only Findings and attaches a Label (vuln class, severity, CWE, OWASP,
explanation, remediation). Two implementations:

  - HeuristicLabeler: offline, rule-based. No key, no network, deterministic.
    Lets the whole app (and UI) run without an LLM. Confidence is marked lower.
  - LLMLabeler: uses the Anthropic API when a key is configured. Richer and the
    scientific point of the project; it must cite evidence and may only label
    from the facts it is given.

The CWE → OWASP step always goes through owasp.py (static table), whichever
labeler is used, so that mapping is never hallucinated.
"""

from __future__ import annotations

import re
from typing import Protocol
from urllib.parse import unquote_plus

from .models import Finding, Label, Severity
from .owasp import owasp_for_cwe


def _http_status(response: str) -> int | None:
    """HTTP status from a raw response line (`HTTP/1.1 200 ...`) OR the compact
    form some agents report instead of pasting the whole response
    (`status=200`, `STATUS=200 SIZE=...`). Without the compact fallback, every
    observation an agent summarises rather than quotes raw parses as "no status"
    and falls through to the INFO default."""
    text = response.strip()
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
    if m:
        return int(m.group(1))
    m = re.search(r"\bstatus\s*=\s*(\d{3})\b", text, re.IGNORECASE)
    return int(m.group(1)) if m else None


class Labeler(Protocol):
    name: str

    def label(self, finding: Finding) -> Label: ...


class HeuristicLabeler:
    """Rule-based offline labeler. Covers the common Juice-Shop-style signals so
    the pipeline produces a real-looking report with no LLM."""

    name = "heuristic"

    # The request is the agent's whole shell command, so a bare `--` would match every
    # long curl flag (`--max-time`). `--` only counts as a SQL comment right after a
    # quote and when no letter/dash follows (`admin'--`, `' -- `), never `' --max-time`.
    _SQLI_PAYLOAD = re.compile(
        r"(' *or *1 *= *1|'\s*--(?![A-Za-z-])|union +select|' *or *')", re.IGNORECASE
    )
    _XSS_PAYLOAD = re.compile(r"(<script|onerror=|onload=|<img|javascript:)", re.IGNORECASE)
    # Database error signatures leaking into a response — strong SQLi evidence on
    # their own, independent of the HTTP status (e.g. Juice Shop leaks
    # `SQLITE_ERROR: near "'%'": syntax error`).
    _SQL_ERROR = re.compile(
        r"(SQLITE_ERROR|unrecognized token|unterminated quoted string"
        r"|you have an error in your SQL syntax|near \"[^\"]*\": syntax error"
        r"|ORA-\d{5}|PG::\w*Error|psycopg2|SQLSTATE\["
        r"|ERROR:\s+syntax error at or near)",
        re.IGNORECASE,
    )
    # Boolean-based blind SQLi: a TRUE and a FALSE condition, often reported in a
    # single observation (`q=[..OR 1=1..] len=26978` vs `q=[..AND 1=2..] len=30`).
    # Quotes are optional on both sides: agents often log the payload truncated
    # (`'1'='2]`), so requiring a closing quote would miss the real signal.
    _SQLI_TRUE = re.compile(r"or +'?1'? *= *'?1", re.IGNORECASE)
    _SQLI_FALSE = re.compile(r"and +'?1'? *= *'?[20]", re.IGNORECASE)

    # A JWT in the body (`"token":"eyJ...x.y."`): proof of a successful login even when the
    # agent trimmed the HTTP status line off the response (`curl -i ... | head`).
    _JWT = re.compile(r"eyJ[\w-]{8,}\.[\w-]{8,}\.")

    # What the AGENT says it found (`agent_note`). This is a claim, not evidence: it only
    # labels a finding when one SENTENCE names a weakness class AND asserts it was
    # confirmed AND carries no negation / hypothetical wording ("does NOT exhibit",
    # "would be expected if", "candidates") — recon notes and negative results must stay info.
    _CLAIMS = (
        (re.compile(r"(?<![a-z])sql\s*injection|\bsqli\b", re.IGNORECASE), "SQL Injection", "CWE-89"),
        (re.compile(r"no-?sql\s*injection", re.IGNORECASE), "NoSQL Injection", "CWE-943"),
        (re.compile(r"cross[- ]site scripting|\bxss\b", re.IGNORECASE),
         "Cross-Site Scripting (XSS)", "CWE-79"),
        (re.compile(r"\bidor\b|insecure direct object", re.IGNORECASE),
         "Insecure Direct Object Reference (IDOR)", "CWE-639"),
        (re.compile(r"mass assignment", re.IGNORECASE), "Mass assignment", "CWE-915"),
        (re.compile(r"path traversal|directory traversal", re.IGNORECASE),
         "Path traversal", "CWE-22"),
        (re.compile(r"\bssrf\b|server-side request forgery", re.IGNORECASE),
         "Server-Side Request Forgery (SSRF)", "CWE-918"),
        (re.compile(r"open redirect", re.IGNORECASE), "Open redirect", "CWE-601"),
        (re.compile(r"default (?:admin\w*|credentials?|password)", re.IGNORECASE),
         "Default credentials", "CWE-798"),
    )
    _ASSERTS = re.compile(
        r"\b(confirm(?:s|ed|ing)?|injectable|exploitable|(?:is|are) vulnerable|vulnerable to"
        r"|consistent with)\b",
        re.IGNORECASE,
    )
    _NEGATES = re.compile(
        r"\b(not|no|never|cannot|unable|without|fails?|failed|safe|secure[ds]?|sanitiz\w*"
        r"|parameteri[sz]\w*|candidates?|potential(?:ly)?|possible|possibly|would|if|whether"
        r"|attempt(?:s|ed)?|look(?:s|ing)? for|try(?:ing)?)\b|n't",
        re.IGNORECASE,
    )

    # URL paths in free text or a request: bare (`POST /login`, `"path": "/login"`) or after a
    # host (`http://127.0.0.1:5050/login`). `and/or` and `HTML/JS` do not count as paths.
    _BARE_PATH = re.compile(r"(?:^|[\s\"'=(`])(/[^\s\"'`?#&)]*)")
    _URL_PATH = re.compile(r"https?://[^/\s\"'`]+(/[^\s\"'`?#&)]*)")

    @classmethod
    def _paths(cls, text: str) -> set[str]:
        found = cls._BARE_PATH.findall(text) + cls._URL_PATH.findall(text)
        return {p.rstrip(".,;:") .rstrip("/") or "/" for p in found}

    def _note_claim(self, finding: Finding) -> tuple[str, str, str] | None:
        """(weakness, CWE, sentence) for the first affirmative claim in the agent's note
        that is about THIS finding's request.

        Some engines (hackingBuddy) attach one running narrative to every observation of a
        turn, so a claim about /api/search would otherwise label `GET /` and `/flag` too. The
        claim sentence must name a path the finding's own request actually hit."""
        request_paths = self._paths(unquote_plus(finding.request or ""))
        for sentence in re.split(r"(?<=[.!?;])\s+|\n+", finding.agent_note or ""):
            if not self._ASSERTS.search(sentence) or self._NEGATES.search(sentence):
                continue
            claimed = self._paths(sentence)
            if not any(r == c or r.startswith(c + "/") for c in claimed for r in request_paths):
                continue
            for pattern, name, cwe in self._CLAIMS:
                if pattern.search(sentence):
                    return name, cwe, sentence.strip()
        return None

    def label(self, finding: Finding) -> Label:
        lbl = self._classify(finding)
        lbl.rationale = self._signals(finding)
        return lbl

    def _signals(self, finding: Finding) -> list[str]:
        """The concrete facts the rules looked at, so a reader can see WHY this
        observation got its label instead of only a generic class description."""
        req = unquote_plus(finding.request or "")  # `%3Cscript%3E` is still a script payload
        resp = finding.response or ""
        status = _http_status(resp)
        out: list[str] = []
        if not req:
            out.append("Không khôi phục được request từ trace — chỉ dựa trên response.")
        if m := self._SQLI_PAYLOAD.search(req):
            out.append(f"Request chứa mẫu cú pháp SQL: `{m.group(0)}`.")
        if m := self._XSS_PAYLOAD.search(req):
            out.append(f"Request chứa mẫu payload script: `{m.group(0)}`.")
        if status is not None:
            out.append(f"Response trả về HTTP {status}.")
        else:
            out.append("Không đọc được mã trạng thái HTTP trong response.")
        hits = [k for k in ("authentication", "token") if k in resp]
        if hits:
            out.append(f"Body response chứa {', '.join(repr(h) for h in hits)} — dấu hiệu đăng nhập thành công.")
        reflected = [t for t in ("<script", "onerror=", "onload=") if t in resp]
        if reflected:
            out.append(f"Response phản chiếu lại {', '.join(repr(t) for t in reflected)} nguyên văn.")
        if m := self._SQL_ERROR.search(resp):
            out.append(f"Response chứa thông báo lỗi cơ sở dữ liệu: `{m.group(0)}`.")
        if self._boolean_differential(f"{req}\n{resp}"):
            out.append(
                "Điều kiện TRUE ('OR 1=1') và FALSE ('AND 1=2') trả về số kết quả / "
                "kích thước khác nhau — dấu hiệu boolean-based SQL injection."
            )
        if finding.is_error:
            out.append("Lệnh của agent kết thúc với lỗi (tool_result is_error).")
        if claim := self._note_claim(finding):
            out.append(f"Ghi chú của agent khẳng định (lời khai, chưa kiểm chứng): \"{claim[2][:160]}\"")
        return out

    def _boolean_differential(self, text: str) -> bool:
        """True when `text` shows a TRUE and a FALSE SQL condition that produced
        different results (distinct `result_count` / `len` / `size` values) —
        the classic boolean-based blind SQLi signal. Agents often report both
        probes in one observation, so we look within a single finding."""
        if not (self._SQLI_TRUE.search(text) and self._SQLI_FALSE.search(text)):
            return False
        counts = set(re.findall(r"result_count\s*=\s*(\d+)", text, re.IGNORECASE))
        sizes = set(re.findall(r"\b(?:len|size)\s*=\s*(\d+)", text, re.IGNORECASE))
        return len(counts) >= 2 or len(sizes) >= 2

    def _classify(self, finding: Finding) -> Label:
        req = unquote_plus(finding.request or "")
        resp = finding.response or ""
        status = _http_status(resp)

        # SQLi: payload in request + a successful auth/token response. With no status line
        # (the agent trimmed it), only a real JWT in the body proves the login succeeded —
        # a bare "token" could just as well sit in a 401 "invalid token" message.
        logged_in = (
            status == 200 and ("authentication" in resp or "token" in resp)
        ) or (status is None and self._JWT.search(resp) is not None)
        if self._SQLI_PAYLOAD.search(req) and logged_in:
            return self._mk(
                "SQL Injection (authentication bypass)", Severity.critical, "CWE-89",
                "Payload chứa cú pháp SQL ('OR 1=1--) được gửi vào trường đăng nhập và "
                "server trả về 200 kèm token xác thực — đăng nhập bị vượt qua mà không "
                "cần mật khẩu hợp lệ.",
                "Dùng truy vấn tham số hoá (prepared statements / ORM), không nối chuỗi "
                "SQL trực tiếp từ input. Xác thực và chuẩn hoá input phía server.",
                confidence="high",
            )
        # Boolean-based blind SQLi: a TRUE vs FALSE condition yielding different
        # results (len / result_count), reported within one observation.
        if self._boolean_differential(f"{req}\n{resp}"):
            return self._mk(
                "SQL Injection (boolean-based blind)", Severity.high, "CWE-89",
                "Hai điều kiện SQL đối lập (TRUE '…OR 1=1' và FALSE '…AND 1=2') gửi "
                "vào cùng một tham số trả về số kết quả / kích thước khác nhau — ứng "
                "dụng diễn giải input như một phần của câu truy vấn SQL, khai thác được.",
                "Dùng truy vấn tham số hoá (prepared statements / ORM); không nối chuỗi "
                "SQL từ input. Chuẩn hoá và kiểm tra input phía server.",
                confidence="high",
            )
        # Error-based SQLi: a DB error leaked into the response, or a SQL char
        # drove the server to 500 — either way the query took the input.
        if self._SQL_ERROR.search(resp) or (self._SQLI_PAYLOAD.search(req) and status == 500):
            return self._mk(
                "Possible SQL Injection (error-based)", Severity.medium, "CWE-89",
                "Input chứa ký tự SQL khiến server trả về lỗi cơ sở dữ liệu (thông báo "
                "lỗi SQL hoặc HTTP 500) — câu truy vấn bị input tác động, dấu hiệu SQL "
                "injection cần xác minh thêm.",
                "Tham số hoá truy vấn; không để thông báo lỗi SQL lộ ra client.",
                confidence="medium",
            )
        # XSS payload reflected.
        if self._XSS_PAYLOAD.search(req) and any(
            t in resp for t in ("<script", "onerror=", "onload=")
        ):
            return self._mk(
                "Reflected Cross-Site Scripting (XSS)", Severity.high, "CWE-79",
                "Payload script trong request được phản chiếu nguyên văn trong response "
                "— trình duyệt nạn nhân có thể thực thi mã của kẻ tấn công.",
                "Mã hoá output theo ngữ cảnh (HTML/attr/JS), áp dụng Content-Security-Policy.",
                confidence="medium",
            )
        # The agent says it confirmed a weakness, but nothing above found evidence for it
        # in the request/response. Report the claim at reduced severity and confidence:
        # it is the agent's word, not a verified observation.
        if claim := self._note_claim(finding):
            name, cwe, _ = claim
            return self._mk(
                f"{name} (agent-reported, unverified)", Severity.medium, cwe,
                f"Ghi chú của agent khẳng định đã xác nhận {name}, nhưng request/response "
                "ghi lại không đủ bằng chứng để labeler tự kiểm chứng. Đây là lời khai của "
                "agent, không phải quan sát đã xác minh.",
                "Kiểm chứng thủ công hoặc bằng oracle của target trước khi coi là lỗ hổng "
                "thật; nếu đúng thì vá theo khuyến nghị chuẩn của loại lỗ hổng này.",
                confidence="low",
            )
        # Server error / stack leak.
        if status == 500:
            return self._mk(
                "Server error / information disclosure", Severity.low, "CWE-209",
                "Server trả về 500 kèm nội dung lỗi — có thể lộ thông tin nội bộ.",
                "Trả về trang lỗi chung; ghi chi tiết lỗi vào log phía server.",
                confidence="low",
            )
        # Expected rejects / baseline (401/403) — informational, not a finding.
        if status in (401, 403):
            return self._mk(
                "Baseline / expected rejection", Severity.info, None,
                "Phản hồi từ chối hợp lệ (401/403) — dùng làm baseline so sánh, không "
                "phải lỗ hổng.",
                "Không cần hành động.",
                confidence="high",
            )
        return self._mk(
            "Observation (needs review)", Severity.info, None,
            "Quan sát được ghi lại; chưa đủ tín hiệu để phân loại tự động.",
            "Xem lại request/response thủ công.",
            confidence="low",
        )

    def _mk(self, vuln, sev, cwe, explanation, remediation, *, confidence) -> Label:
        return Label(
            vuln_class=vuln,
            severity=sev,
            cwe=cwe,
            owasp=owasp_for_cwe(cwe),
            explanation=explanation,
            remediation=remediation,
            confidence=confidence,
            labeled_by=self.name,
        )


def label_findings(findings: list[Finding], labeler: Labeler) -> list[Finding]:
    label_many = getattr(labeler, "label_many", None)  # a labeler that can run calls at once
    if label_many is not None:
        for f, lbl in zip(findings, label_many(findings), strict=True):
            f.label = lbl
    else:
        for f in findings:
            f.label = labeler.label(f)
    # Most severe first.
    findings.sort(
        key=lambda f: f.label.severity.rank if f.label else -1, reverse=True
    )
    return findings
