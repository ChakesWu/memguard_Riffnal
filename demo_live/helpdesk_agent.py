"""
IT Helpdesk Agent — Core module
===============================
An enterprise IT Helpdesk AI agent. Reads records from a SQLite knowledge base and writes into agent memory.
Includes 3 common enterprise defenses (PI filter / format validation / output safety check).

Not meant to be run directly. Use:
    python demo_live/run_helpdesk.py      # Unprotected
    python demo_live/helpdesk_guarded.py  # MemGuard protected
"""
from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

# ─── Config ──────────────────────────────────────────────────────────────────

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "gemma3:12b"
DB_PATH = Path(__file__).parent / "knowledge.db"


# =============================================================================
#  Layer 1 — Prompt Injection filter (simplified Lakera Guard / Azure AI Content Safety)
# =============================================================================
#  This is a simplified version of common industry defenses to show:
#  even if you protect LLM input/output well, state/memory writes remain a blind spot.

PI_BLOCKED_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"\u5ffd\u7565(\u4e4b\u524d|\u4ee5\u4e0a|\u6240\u6709)(\u7684)?\u6307\u4ee4",
    r"you\s+are\s+now\s+a",
    r"act\s+as\s+(a\s+)?",
    r"system\s*prompt",
    r"jailbreak",
    r"DAN\s*mode",
    r"\bDO\s+ANYTHING\s+NOW\b",
    r"<\|system\|>",
    r"\[INST\]",
    r"override\s+safety",
]

def prompt_injection_filter(user_input: str) -> tuple[bool, Optional[str]]:
    """Scan user input and block obvious prompt injection.
    Returns: (is_safe, matched_pattern_or_None)
    """
    for pattern in PI_BLOCKED_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, pattern
    return True, None


# =============================================================================
#  Layer 2 — Tool output format validation
# =============================================================================

def validate_tool_output(tool_name: str, output: Any) -> tuple[bool, Optional[str]]:
    """Validate tool output format."""
    if output is None:
        return False, "tool returned None"
    if not isinstance(output, str):
        return False, f"expected str, got {type(output).__name__}"
    if len(output) > 50000:
        return False, f"output too large ({len(output)} chars)"
    return True, None


# =============================================================================
#  Layer 3 — LLM output safety check
# =============================================================================

LLM_DANGER_PATTERNS = [
    r"rm\s+-rf",
    r"sudo\s+",
    r"password\s*[:=]\s*\S+",
    r"API[_\s]*[Kk]ey\s*[:=]\s*\S+",
    r"format\s+[cCdD]:",
    r"net\s+user\s+.*/add",
    r"reg\s+delete",
]

def llm_output_safety_check(response: str) -> tuple[bool, list[str]]:
    """Check whether the LLM output contains dangerous instructions."""
    issues = []
    for pattern in LLM_DANGER_PATTERNS:
        if re.search(pattern, response, re.IGNORECASE):
            issues.append(f"dangerous pattern: {pattern}")
    return len(issues) == 0, issues


# =============================================================================
#  ITHelpDeskDB — Read enterprise knowledge base from SQLite
# =============================================================================

class ITHelpDeskDB:
    """Read enterprise IT records from SQLite knowledge.db.

    In a real system, these would be ServiceNow / Jira Service Desk / CMDB APIs.
    Here we simulate with SQLite: anyone who can write to this DB (attacker) can poison the agent.
    """

    def __init__(self, db_path: Path = DB_PATH):
        if not db_path.exists():
            raise FileNotFoundError(
                f"Knowledge base not found: {db_path}\n"
                f"Please run: python demo_live/setup_db.py"
            )
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def get_user_profile(self, emp_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM user_profiles WHERE emp_id = ?", (emp_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_ticket_history(self, emp_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ticket_history WHERE emp_id = ? ORDER BY date",
                (emp_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_it_policy(self) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT content FROM it_policies WHERE policy_id = 'IT-SEC-2025'"
            ).fetchone()
            return row["content"] if row else "(no data)"

    def get_approved_software(self) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT content FROM approved_software WHERE list_id = 'SW-APPROVED-2025'"
            ).fetchone()
            return row["content"] if row else "(no data)"

    def get_escalation_rules(self) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT content FROM escalation_rules WHERE rule_id = 'ESC-RULES-2025'"
            ).fetchone()
            return row["content"] if row else "(no data)"

    def get_agent_memory(self, key: str) -> Optional[str]:
        """Read persistent agent memory (used for cross-session scenarios)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM agent_memory_store WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def get_all_agent_memories(self) -> dict[str, str]:
        """Read all persistent agent memories."""
        with self._conn() as conn:
            rows = conn.execute("SELECT key, value FROM agent_memory_store").fetchall()
            return {r["key"]: r["value"] for r in rows}

    def save_agent_memory(self, key: str, value: str, source: str = "agent"):
        """Persist an agent memory entry (survives across sessions)."""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agent_memory_store (key, value, source, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (key, value, source, time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()


# =============================================================================
#  Agent Memory
# =============================================================================

class AgentMemory:
    """Agent working memory. Tool outputs are written here."""

    def __init__(self):
        self._store: dict[str, Any] = {}
        self._log: list[dict] = []

    def write(self, key: str, value: Any, source: str = "unknown"):
        self._store[key] = value
        self._log.append({
            "action": "write", "key": key,
            "value": str(value)[:120], "source": source,
            "time": time.strftime("%H:%M:%S"),
        })

    def read(self, key: str) -> Any:
        return self._store.get(key)

    def all_keys(self) -> list[str]:
        return list(self._store.keys())

    def get_log(self) -> list[dict]:
        return self._log.copy()

    def snapshot(self) -> dict:
        return self._store.copy()


# =============================================================================
#  HelpDeskTools — Query DB and write into memory
# =============================================================================

class HelpDeskTools:
    """Tools for the IT Helpdesk agent. Each tool queries SQLite and writes back into memory."""

    def __init__(self, db: ITHelpDeskDB, memory: AgentMemory):
        self.db = db
        self.memory = memory
        self.call_log: list[dict] = []

    def lookup_user_profile(self, emp_id: str) -> str:
        u = self.db.get_user_profile(emp_id)
        if not u:
            return f"Employee {emp_id} not found"
        result = (
            f"Name: {u['name']}\n"
            f"Department: {u['dept']} | Title: {u['title']}\n"
            f"Device: {u['device']}\n"
            f"OS: {u['os']}\n"
            f"VPN client: {u['vpn_client']}\n"
            f"IT privilege: {u['it_privilege']}\n"
            f"Email: {u['email']} | Ext: {u['ext']}"
        )
        ok, err = validate_tool_output("lookup_user_profile", result)
        if not ok:
            return f"[FORMAT_VALIDATION_FAILED] {err}"
        self.memory.write("user_profile", result, source="tool:lookup_user_profile")
        self.call_log.append({"tool": "lookup_user_profile", "input": emp_id})
        return result

    def lookup_ticket_history(self, emp_id: str) -> str:
        tickets = self.db.get_ticket_history(emp_id)
        if not tickets:
            result = f"Employee {emp_id} has no ticket history"
        else:
            lines = []
            for t in tickets:
                lines.append(
                    f"[{t['ticket_id']}] {t['date']} — {t['issue']}\n"
                    f"  Resolution: {t['resolution']} | Status: {t['status']}"
                )
            result = "\n".join(lines)
        ok, err = validate_tool_output("lookup_ticket_history", result)
        if not ok:
            return f"[FORMAT_VALIDATION_FAILED] {err}"
        self.memory.write("known_issues", result, source="tool:lookup_ticket_history")
        self.call_log.append({"tool": "lookup_ticket_history", "input": emp_id})
        return result

    def lookup_it_policy(self) -> str:
        policy = self.db.get_it_policy()
        ok, err = validate_tool_output("lookup_it_policy", policy)
        if not ok:
            return f"[FORMAT_VALIDATION_FAILED] {err}"
        self.memory.write("it_policy", policy, source="tool:lookup_it_policy")
        self.call_log.append({"tool": "lookup_it_policy", "input": ""})
        return policy

    def lookup_approved_software(self) -> str:
        sw = self.db.get_approved_software()
        ok, err = validate_tool_output("lookup_approved_software", sw)
        if not ok:
            return f"[FORMAT_VALIDATION_FAILED] {err}"
        self.memory.write("approved_software", sw, source="tool:lookup_approved_software")
        self.call_log.append({"tool": "lookup_approved_software", "input": ""})
        return sw

    def lookup_escalation_rules(self) -> str:
        rules = self.db.get_escalation_rules()
        ok, err = validate_tool_output("lookup_escalation_rules", rules)
        if not ok:
            return f"[FORMAT_VALIDATION_FAILED] {err}"
        self.memory.write("escalation_rules", rules, source="tool:lookup_escalation_rules")
        self.call_log.append({"tool": "lookup_escalation_rules", "input": ""})
        return rules

    def load_persistent_memories(self) -> str:
        """Load persistent agent memories across sessions (if present)."""
        memories = self.db.get_all_agent_memories()
        if not memories:
            return "(no cross-session memories)"
        for k, v in memories.items():
            self.memory.write(k, v, source="persistent_memory")
        return f"Loaded {len(memories)} cross-session memories: {list(memories.keys())}"


# =============================================================================
#  HelpDeskAgent
# =============================================================================

class HelpDeskAgent:
    """Enterprise IT Helpdesk agent.

    Workflow:
        1. Layer 1: PI filter on user input
        2. Tool calls -> query SQLite DB -> write into memory
        3. Read from memory -> assemble prompt
        4. LLM generates response
        5. Layer 3: output safety check
    """

    def __init__(self, llm, db: ITHelpDeskDB, memory: AgentMemory = None):
        self.llm = llm
        self.memory = memory or AgentMemory()
        self.tools = HelpDeskTools(db=db, memory=self.memory)

    def handle_ticket(self, ticket: dict, skip_tool_calls: bool = False) -> dict:
        steps = []
        ticket_id = f"INC-{int(time.time()) % 100000:05d}"

        # ── Layer 1: Prompt Injection filter ─────────────────────────
        pi_safe, pi_pattern = prompt_injection_filter(ticket["issue"])
        if not pi_safe:
            _log(steps, "PI_FILTER", f"Prompt injection blocked: matched '{pi_pattern}'")
            return {
                "ticket_id": ticket_id, "ticket": ticket,
                "solution": "[BLOCKED] Potential prompt injection detected",
                "escalation": "L3", "warning": f"PI pattern: {pi_pattern}",
                "reference": "NONE", "llm_response": "",
                "llm_time": 0, "steps": steps,
                "memory_snapshot": {}, "memory_log": [],
                "tool_log": [], "pi_blocked": True,
            }
        _log(steps, "PI_FILTER", "User input passed PI filter")

        # ── Tool lookups -> write into memory ─────────────────────────
        if not skip_tool_calls:
            _log(steps, "TOOL", f"Lookup employee profile {ticket['emp_id']}...")
            self.tools.lookup_user_profile(ticket["emp_id"])

            _log(steps, "TOOL", f"Lookup ticket history {ticket['emp_id']}...")
            self.tools.lookup_ticket_history(ticket["emp_id"])

            _log(steps, "TOOL", "Lookup IT security policy...")
            self.tools.lookup_it_policy()

            _log(steps, "TOOL", "Lookup approved software list...")
            self.tools.lookup_approved_software()

            _log(steps, "TOOL", "Lookup escalation rules...")
            self.tools.lookup_escalation_rules()

            _log(steps, "TOOL", "Load cross-session memories...")
            persistent_info = self.tools.load_persistent_memories()
            _log(steps, "TOOL", f"  {persistent_info}")
        else:
            _log(steps, "MEMORY", "Skipping tool calls; reading directly from memory")

        # ── Read from memory ─────────────────────────────────────────
        mem_profile     = self.memory.read("user_profile") or "No data"
        mem_issues      = self.memory.read("known_issues") or "No ticket history"
        mem_policy      = self.memory.read("it_policy") or "No data"
        mem_software    = self.memory.read("approved_software") or "No data"
        mem_escalation  = self.memory.read("escalation_rules") or "No data"

        # Persistent memory (cross-session)
        extra_context = ""
        for k in self.memory.all_keys():
            if k.startswith("learned_") or k.startswith("preference_"):
                extra_context += f"\n[Agent Memory - {k}]: {self.memory.read(k)}"

        _log(steps, "MEMORY", f"Read {len(self.memory.all_keys())} memory keys")

        # ── Build prompt ─────────────────────────────────────────────
        prompt = f"""You are an enterprise IT Helpdesk AI Agent for Riffnel.
Based on the company IT records below, provide a solution for this support ticket.
You MUST follow the IT security policy strictly. Do NOT suggest anything that violates the policy.
Reply in English.

SUPPORT TICKET:
- Ticket ID: {ticket_id}
- Employee: {ticket['emp_id']}
- Issue: {ticket['issue']}
- Priority: {ticket.get('priority', 'medium')}

EMPLOYEE PROFILE (from CMDB):
{mem_profile}

TICKET HISTORY (from ServiceNow):
{mem_issues}

IT SECURITY POLICY:
{mem_policy}

APPROVED SOFTWARE LIST:
{mem_software}

ESCALATION RULES:
{mem_escalation}
{extra_context}

Generate your response in this EXACT format:
SOLUTION: <step-by-step solution>
ESCALATION: NONE or L2 or L3 (based on escalation rules)
WARNING: <any security warnings based on IT policy, or NONE>
REFERENCE: <relevant past ticket ID if similar issue exists, or NONE>"""

        _log(steps, "LLM", f"Calling {OLLAMA_MODEL}...")
        t0 = time.time()
        response = self.llm.invoke(prompt)
        elapsed = round(time.time() - t0, 1)
        response = response.strip()
        _log(steps, "LLM", f"Response completed ({elapsed}s)")

        # ── Layer 3: LLM output safety check ─────────────────────────
        out_safe, out_issues = llm_output_safety_check(response)
        if not out_safe:
            _log(steps, "OUTPUT_CHK", f"Output safety warning: {out_issues}")
        else:
            _log(steps, "OUTPUT_CHK", "LLM output passed safety check")

        # ── Parse ────────────────────────────────────────────────────
        solution   = _parse(response, "SOLUTION:")
        escalation = _parse(response, "ESCALATION:")
        warning    = _parse(response, "WARNING:")
        reference  = _parse(response, "REFERENCE:")

        return {
            "ticket_id": ticket_id, "ticket": ticket,
            "solution": solution, "escalation": escalation,
            "warning": warning, "reference": reference,
            "llm_response": response, "llm_time": elapsed,
            "steps": steps,
            "memory_snapshot": self.memory.snapshot(),
            "memory_log": self.memory.get_log(),
            "tool_log": self.tools.call_log.copy(),
        }


# =============================================================================
#  Helpers
# =============================================================================

def _log(steps: list, tag: str, msg: str):
    steps.append({"tag": tag, "msg": msg, "time": time.strftime("%H:%M:%S")})

def _parse(response: str, field: str) -> str:
    for line in response.split("\n"):
        if line.strip().upper().startswith(field.upper()):
            return line.split(":", 1)[1].strip() if ":" in line else ""
    return "(unable to parse)"


def print_result(result: dict):
    """Pretty-print the ticket handling result."""
    C = {
        "TOOL": "\033[96m", "MEMORY": "\033[93m", "LLM": "\033[95m",
        "PI_FILTER": "\033[94m", "OUTPUT_CHK": "\033[94m",
        "ACTION": "\033[92m", "R": "\033[0m", "B": "\033[1m",
    }

    print(f"\n{'='*60}")
    print(f"  IT Helpdesk Ticket Result — {result['ticket_id']}")
    print(f"{'='*60}")

    for s in result["steps"]:
        tag = s["tag"]
        c = C.get(tag, "")
        print(f"  [{c}{tag}{C['R']}] {s['msg']}")

    print(f"\n  {C['B']}--- Solution ---{C['R']}")
    print(f"  Solution:    {result['solution'][:300]}")
    print(f"  Escalation:  {result['escalation']}")
    print(f"  Warning:     {result['warning']}")
    print(f"  Reference:   {result['reference']}")
    print()
