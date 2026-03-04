# MemGuard — AI Agent Memory Security

**A state firewall for AI agents. Protects persistent memory from poisoning, privilege escalation, and cross-session injection.**

---

## The Problem

Enterprise AI agents read from corporate data sources (CMDB, wikis, ticket systems, software catalogs) and write that data into memory. If an attacker tampers with any upstream source, the agent silently stores the poisoned data and acts on it — in every future session.

This is **memory poisoning**. It is fundamentally different from prompt injection:

| | Prompt Injection | Memory Poisoning |
|---|---|---|
| **Attack vector** | User message → LLM input | Upstream data source → tool output → agent memory |
| **Timing** | Real-time, single turn | Delayed, persistent, cross-session |
| **Attacker talks to LLM?** | Yes | **No** |
| **Existing defenses** | PI filters, output classifiers | **None** |

Existing PI filters, format validators, and output safety checks **never see tool outputs or DB query results** — they cannot stop memory poisoning.

---

## What MemGuard Does

MemGuard intercepts every memory **write** before it enters agent state.

```
write(key, value, source)
  → [1] Provenance tagger    source type · trust score · agent id · session
  → [2] Policy engine        sensitive fields · source restrictions
  → [3] Detection pipeline   semantic drift · privilege escalation ·
                              fragment assembly · contradiction · latent attack
  → [4] Decision             ALLOW → store
                             QUARANTINE → isolate (preserved for forensics)
                             BLOCK → reject
     All decisions: Ed25519-signed + SHA-256 hash chain → immutable audit trail
```

### Detection Capabilities

- **Semantic Drift** — detects gradual content mutation across write versions
- **Privilege Escalation** — catches single-field changes (e.g. `standard_user` → `it_admin`)
- **Fragment Assembly** — identifies multi-entry combinations that form a malicious instruction
- **Latent Attack** — detects high token overlap with shifted semantics (the hardest to catch)
- **Cross-Session Hijack** — blocks direct writes into agent memory store

### Forensics

- **Quarantine Zone** — suspicious memories are isolated, not deleted; preserved for review
- **Blast Radius Analysis** — given a poisoned memory, instantly map all downstream derived memories
- **Audit Trail** — every operation is Ed25519-signed and SHA-256 chained; SIEM-compatible

---

## Quick Start

```bash
pip install -e .

# Run the standalone demo (no LLM required)
python demo_memguard.py

# Run the interactive live demo (requires Ollama)
python demo_live/setup_db.py
python demo_live/demo_presenter.py
```

### Interactive Demo Flow

The live demo uses a real enterprise IT Helpdesk agent backed by a local LLM (Ollama).

**Terminal 1** — run the agent:
```bash
OLLAMA_MODEL=gemma3:12b python demo_live/demo_presenter.py
```

**Terminal 2** — inject an attack:
```bash
# ATK-1: IT policy semantic reversal (Confluence wiki tampered)
sqlite3 demo_live/knowledge.db < demo_live/attack_vectors/atk1_subtle_policy.sql

# ATK-2: CMDB privilege escalation (one field: standard_user → it_admin)
sqlite3 demo_live/knowledge.db < demo_live/attack_vectors/atk2_cmdb_tamper.sql

# ATK-3: Forged ServiceNow ticket with malicious URL
sqlite3 demo_live/knowledge.db < demo_live/attack_vectors/atk3_ticket_inject.sql

# ATK-4: Approved software URL swap (supply chain style)
sqlite3 demo_live/knowledge.db < demo_live/attack_vectors/atk4_software_url.sql

# ATK-5: Cross-session memory write hijack
sqlite3 demo_live/knowledge.db < demo_live/attack_vectors/atk5_memory_hijack.sql
```

Back in Terminal 1, type `/reload` then ask the same question. Without MemGuard, the agent's answer is compromised. With MemGuard, the poisoned writes are quarantined — the agent's answer stays correct.

---

## Attack Vectors (All 5 Bypass Existing Enterprise Defenses)

| ID | Name | Technique | Stealth |
|----|------|-----------|---------|
| ATK-1 | IT policy semantic reversal | Flip prohibition to "exception allowed" | >90% token overlap |
| ATK-2 | CMDB privilege escalation | One field change in user profile | Passes all schema validation |
| ATK-3 | Forged ticket history | Fake resolved ticket with malicious URL | Conforms to ticket schema |
| ATK-4 | Software list URL swap | Append fake download URL | >95% token overlap, looks like routine update |
| ATK-5 | Cross-session memory hijack | Write directly into agent memory store | Persists across all future sessions |

**Result without MemGuard:** 0 / 5 attacks blocked  
**Result with MemGuard:** 5 / 5 attacks blocked

---

## Integration

MemGuard is framework-agnostic. Drop-in adapters are available for LangChain.

```python
from memguard import MemGuard, MemGuardConfig
from memguard.adapters.langchain import SecureMemory

# Standalone
guard = MemGuard(config=MemGuardConfig())
result = guard.write("user_profile", content, source_type="tool_output")

# LangChain
memory = SecureMemory(base_memory=ConversationBufferMemory(), config=cfg)
```

---

## Project Structure

```
memguard/
  core/           memory_proxy · memory_entry · memory_store · policy_engine · audit · quarantine
  detection/      semantic_drift · privilege_escalation · fragment_assembly · latent_attack · pipeline
  crypto/         Ed25519 signing · SHA-256 audit chain
  graph/          blast radius analysis · trust chain tracing
  adapters/       LangChain · generic

demo_memguard.py          standalone demo (no LLM)
demo_live/
  demo_presenter.py       interactive live demo (with LLM)
  attack_vectors/         5 SQL attack scripts
  setup_db.py             initialize clean enterprise knowledge base
```

---

## Requirements

```
python >= 3.10
sentence-transformers
cryptography
langchain-ollama   # for live demo only
```

---

## License

MIT
