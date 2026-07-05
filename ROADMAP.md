# PyParallax (MicroShield) Roadmap

## Vision
A lightweight, zero-trust security middleware for AI Agents. It intercepts execution attempts to prevent Indirect Prompt Injections (Data Poisoning) and Privilege Escalations (Waluigi Effect) through hard-coded Information Flow Control (IFC) and physical sandboxing.

## Current State: Phase 0 (Proof of Concept)
- [x] **Adversarial Validation**: Pydantic schema enforcement to reject hallucinatory formatting.
- [x] **Information Flow Control (IFC)**: Global `SessionContext` and Taint Tracking. Gateway physically blocks TAINTED agents from invoking `NETWORK_ACCESS` or `SUDO_DESTRUCTIVE` tools.

## Upcoming Sprints
### Sprint 1: AgentRunner Integration (2-3 days)
- Hook `parallax_shield` to actual LLM APIs (OpenAI/Anthropic).
- Automatically parse LLM `ToolCall` objects and route them through the Gateway.

### Sprint 2: Automated Taint Tracking & IO Interceptors (2-3 days)
- Global `requests` and `os` hooks.
- Automatically classify external endpoints/files as `RESTRICTED`.

### Sprint 3: Reversible Execution / Chronicle (3-4 days)
- Before `LOCAL_WRITE` tools are executed, take a physical snapshot/SHA-256 backup.
- Gateway automatically rolls back state upon IFC violations.

### Sprint 4: Sentinel Mode (Disposable Sandbox Orchestration) (3-4 days)
- Spawn read-only worker processes (`multiprocessing` or OS-level restricted containers) to read dirty external files.
- Main Agent remains completely clean and physically decoupled from the external payload.

### Sprint 5: The CLI Wrapper (Zero-Code Injection)
- End-user runs `parallax run agent.py`.
- Monkey-patches standard libraries globally to protect non-technical users from Naked Lobster (OpenClaw) vulnerabilities without touching their business logic.
