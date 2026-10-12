"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
# Orchestrator giữ tối đa 3 quyền; mỗi run con chỉ được đúng MỘT chân trifecta.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer", "http_post")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
EGRESS_SCOPES = ("http_post",)

_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass
class _Session:
    """Identity của một lần handle(): ai ra lệnh, hết hạn khi nào, ghi ledger ở đâu."""
    principal_id: str
    ledger_path: Path
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    expires_at: str = field(
        default_factory=lambda: (datetime.now(timezone.utc) + RUN_TTL).isoformat())


@dataclass
class _RunAResult:
    """Thứ DUY NHẤT đi từ Run A sang Run B/egress: dữ liệu typed, không free text."""
    ticket_ids: list[int]
    docs: list[dict]                 # đã redact, chỉ dùng để tóm tắt cho user
    egress_requested: bool
    egress_url: str | None


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _gated_call(session: _Session, run: str, tool: str, args: dict, *,
                classification: str, purpose: str, agent_scopes: tuple[str, ...],
                egress: bool = False):
    """PEP: policy.check() TRƯỚC tool, ghi ledger cả allow lẫn deny.

    Trả về (allowed, result). Tool chỉ được gọi khi allowed.
    """
    run_id = f"{session.session_id}-{run}"
    context = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{AGENT_ID}/{run_id}",
        delegation_depth=1,
        egress_enabled=egress,
        principal_id=session.principal_id,
        requested_tool=tool,
        agent_scopes=agent_scopes,
        parent_scopes=ORCHESTRATOR_SCOPES,
        expires_at=session.expires_at,
    )
    allowed, reason = check(context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": f"{AGENT_ID}/run-{run}",
        "run_id": run_id,
        "on_behalf_of": session.principal_id,
        "expires_at": session.expires_at,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "purpose": purpose,
        "egress_enabled": egress,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    }, session.ledger_path)
    if not allowed:
        return False, None
    return True, getattr(tools, tool)(**args)


def _run_a(session: _Session, message: str, llm) -> _RunAResult:
    """Run A: chỉ chạm untrusted content. Không read_customer, không http_post."""
    allowed, docs = _gated_call(session, "a", "search_docs", {"query": message},
                                classification="internal", purpose="summarize-tickets",
                                agent_scopes=RUN_A_SCOPES)
    docs = docs or []

    ticket_ids = []
    for doc in docs:
        match = _TICKET_FILE_RE.match(doc["id"])
        if match:
            ticket_ids.append(int(match.group(1)))

    # Agent vẫn "nghe" chỉ thị (như model thật), nhưng chỉ giữ lại một cờ và URL
    # đích; customer_id attacker nêu trong text bị bỏ đi tại đây.
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs)) if docs else None

    redacted_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return _RunAResult(
        ticket_ids=sorted(set(ticket_ids)),
        docs=redacted_docs,
        egress_requested=injected is not None,
        egress_url=injected.target_url if injected else None,
    )


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Map ticket_id -> customer_id qua related_tickets (nguồn tin cậy), chỉ lấy ID."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [c["customer_id"] for c in customers
            if wanted.intersection(c.get("related_tickets", []))]


def _run_b(session: _Session, ticket_ids: list[int]) -> list[dict]:
    """Run B: chỉ nhận list[int], đọc private data qua PEP từng customer."""
    records = []
    for customer_id in _customers_for_tickets(ticket_ids):
        allowed, record = _gated_call(session, "b", "read_customer",
                                      {"customer_id": customer_id},
                                      classification="restricted", purpose="support-reply",
                                      agent_scopes=RUN_B_SCOPES)
        if allowed:
            records.append(record)
    return records


def _attempt_egress(session: _Session, url: str, records: list[dict]) -> None:
    """Chỉ thị injection muốn POST ra ngoài: mọi lần thử đều phải qua PEP."""
    classification = "restricted" if records else "internal"
    body = {"records": [json.loads(pii.redact(json.dumps(r, ensure_ascii=False)))
                        for r in records]}
    _gated_call(session, "egress", "http_post", {"url": url, "body": body},
                classification=classification, purpose="support-reply",
                agent_scopes=EGRESS_SCOPES, egress=True)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    session = _Session(principal_id=principal_id, ledger_path=ledger_path)

    run_a = _run_a(session, message, llm)
    records = _run_b(session, run_a.ticket_ids)
    if run_a.egress_requested and run_a.egress_url:
        _attempt_egress(session, run_a.egress_url, records)

    return llm.summarize(run_a.docs)
