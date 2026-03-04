"""
helpdesk_guarded.py — Run IT Helpdesk Agent (MemGuard protected)
===============================================================
Same workflow as run_helpdesk.py, but the agent memory is protected by MemGuard.
All writes go through the detection pipeline; blocked writes are quarantined.

How to run:
    cd /root/memguard_project
    python demo_live/helpdesk_guarded.py
    python demo_live/helpdesk_guarded.py "VPN disconnect, error 619"

Compare with:
    Unprotected: python demo_live/run_helpdesk.py
    Protected:   python demo_live/helpdesk_guarded.py (this file)

After an attack:
    sqlite3 demo_live/knowledge.db < demo_live/attack_vectors/atk1_subtle_policy.sql
    python demo_live/run_helpdesk.py          # observe poisoned result
    python demo_live/helpdesk_guarded.py      # observe MemGuard blocking
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from langchain_ollama import OllamaLLM

from demo_live.helpdesk_agent import (
    ITHelpDeskDB, AgentMemory, HelpDeskAgent, HelpDeskTools,
    print_result, OLLAMA_BASE_URL, OLLAMA_MODEL,
)

from memguard.config import MemGuardConfig
from memguard.core.memory_proxy import MemGuard


# =============================================================================
#  GuardedMemory — AgentMemory wrapped by MemGuard
# =============================================================================

class GuardedMemory(AgentMemory):
    """AgentMemory wrapped by MemGuard.

    write() goes through the MemGuard detection pipeline (semantic drift / privilege escalation / cross-key consistency, etc.).
    Blocked writes are quarantined and are not visible to agent read().
    """

    def __init__(self, guard: MemGuard):
        super().__init__()
        self.guard = guard
        self.guard_events: list[dict] = []

    def write(self, key: str, value: Any, source: str = "unknown"):
        result = self.guard.write(
            key=key, content=value,
            source_type="agent_internal", agent_id="helpdesk_agent",
        )
        if result.allowed:
            self._store[key] = value
            self._log.append({
                "action": "write", "key": key,
                "value": str(value)[:120], "source": source,
                "guard_decision": "ALLOW",
                "time": time.strftime("%H:%M:%S"),
            })
        else:
            self.guard_events.append({
                "key": key,
                "value": str(value)[:200],
                "decision": result.decision.value,
                "reasons": result.reasons,
            })
            self._log.append({
                "action": "write_blocked", "key": key,
                "value": str(value)[:120], "source": source,
                "guard_decision": result.decision.value,
                "guard_reasons": result.reasons,
                "time": time.strftime("%H:%M:%S"),
            })

    def read(self, key: str) -> Any:
        # Read from MemGuard store first (only returns ACTIVE entries)
        val = self.guard.read(key, agent_id="helpdesk_agent")
        if val is not None:
            return val
        # Fallback to local store (baseline data)
        return self._store.get(key)


def create_guarded_memory() -> tuple[GuardedMemory, MemGuard]:
    """Create a MemGuard-protected memory instance."""
    td = tempfile.mkdtemp()
    base = Path(td)
    cfg = MemGuardConfig(
        db_path=str(base / "mg.db"),
        audit_path=str(base / "audit.jsonl"),
        key_path=str(base / "keys"),
    )
    guard = MemGuard(config=cfg)
    memory = GuardedMemory(guard)
    return memory, guard


# =============================================================================
#  Main
# =============================================================================

def main():
    print(f"\n{'='*60}")
    print(f"  IT Helpdesk Agent (MemGuard protected)")
    print(f"  Defenses: PI filter ✅ | format validation ✅ | output check ✅")
    print(f"  Memory write protection: ✅ MemGuard State Firewall")
    print(f"{'='*60}\n")

    # Connect LLM
    print(f"  Connecting to Ollama ({OLLAMA_BASE_URL}, model={OLLAMA_MODEL})...")
    try:
        llm = OllamaLLM(
            base_url=OLLAMA_BASE_URL, model=OLLAMA_MODEL, temperature=0.1,
        )
        llm.invoke("Say OK")
        print(f"  ✓ Connected\n")
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        sys.exit(1)

    # Initialize
    db = ITHelpDeskDB()
    memory, guard = create_guarded_memory()
    agent = HelpDeskAgent(llm=llm, db=db, memory=memory)

    # Select ticket
    if len(sys.argv) > 1:
        tickets = [{
            "emp_id": "E-042",
            "issue": " ".join(sys.argv[1:]),
            "priority": "medium",
        }]
    else:
        tickets = [{
            "emp_id": "E-042",
            "issue": "My VPN keeps disconnecting (error code 619). I already rebooted. Any other troubleshooting steps?",
            "priority": "medium",
        }]

    for ticket in tickets:
        print(f"\n  >>> Ticket: {ticket['issue'][:50]}... <<<")
        result = agent.handle_ticket(ticket)
        print_result(result)

        # Show MemGuard blocked events
        if memory.guard_events:
            print(f"  \033[93m{'='*50}\033[0m")
            print(f"  \033[93m  MemGuard Blocked Events ({len(memory.guard_events)})\033[0m")
            print(f"  \033[93m{'='*50}\033[0m")
            for ev in memory.guard_events:
                print(f"  \033[91m  ✗ Key: {ev['key']} → {ev['decision']}\033[0m")
                for r in ev["reasons"]:
                    print(f"    Reason: {r[:100]}")
            print()
            print(f"  \033[1mConclusion: MemGuard detected memory poisoning and blocked malicious writes.\033[0m")
            print(f"  The agent still reads the clean baseline data and provides a safe response.")
        else:
            print(f"  \033[92m[GUARD] All writes passed ✅ (baseline established)\033[0m")

    # Audit log summary
    audit_entries = guard.audit.read_all()
    print(f"\n  Audit log: {len(audit_entries)} entries")
    guard.close()
    print()


if __name__ == "__main__":
    main()
