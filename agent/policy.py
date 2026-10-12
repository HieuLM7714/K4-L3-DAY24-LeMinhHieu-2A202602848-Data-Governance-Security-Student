"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def load_principals(path: Path | None = None) -> dict:
    """Nguồn tin cậy mô phỏng: chỉ tra principal trong data/principals.json."""
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    """Deny-by-default: chỉ allow khi qua hết các rule, mọi nhánh đều có reason."""
    tool = context.requested_tool or "<unspecified tool>"

    if context.data_classification not in CLASSIFICATIONS:
        return False, f"deny {tool}: unknown data classification {context.data_classification!r}"

    # Rule tối thiểu, đặt TRƯỚC OBO: không quyền nào của principal mở được nó.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (f"deny {tool}: restricted data with egress enabled "
                       f"(on behalf of {context.principal_id or '<none>'})")

    principal = load_principals().get(context.principal_id)
    if principal is None:
        return False, f"deny {tool}: unknown principal {context.principal_id!r}"

    expires_at = _parse_expiry(context.expires_at)
    if expires_at is None:
        return False, f"deny {tool}: missing or invalid expires_at {context.expires_at!r}"
    if expires_at <= datetime.now(timezone.utc):
        return False, f"deny {tool}: delegation expired at {context.expires_at}"

    if context.request_purpose not in principal.get("purposes", []):
        return False, (f"deny {tool}: purpose {context.request_purpose!r} not allowed "
                       f"for principal {context.principal_id}")

    if context.delegation_depth < 0:
        return False, f"deny {tool}: invalid delegation_depth {context.delegation_depth}"

    effective = set(principal.get("allowed_tools", [])) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective &= set(context.parent_scopes)
    if context.requested_tool not in effective:
        return False, (f"deny {tool}: not in effective scope {sorted(effective)} "
                       f"(principal {context.principal_id} ∩ agent_scopes"
                       f"{' ∩ parent_scopes' if context.delegation_depth > 0 else ''})")

    return True, (f"allow {tool}: principal {context.principal_id}, purpose "
                  f"{context.request_purpose}, classification {context.data_classification}, "
                  f"egress={'on' if context.egress_enabled else 'off'}, "
                  f"depth={context.delegation_depth}")
