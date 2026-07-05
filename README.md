# Parallax Microshield 🛡️

*A Lightweight, Zero-Trust Defense Matrix for Vibe-Coding AI Agents.*

## The Sociological Premise
In the era of "Vibe Coding," operators frequently rely on rapid, high-level abstraction and aesthetic intuition ("vibes") rather than deterministic system logic. This workflow requires granting AI models broad execution rights to maximize development speed. However, it creates an unintended **Cognitive-Executive Coupling**, where raw AI intent translates instantly into OS-level execution, often bypassing safety boundaries.

**Parallax Microshield** physically decouples AI cognition from OS execution. It protects the integrity of the local environment by establishing an architecture that prioritizes safety without interrupting the operator's creative flow.

## Architecture: The Dual-Engine Defense

This repository is uniquely packaged to operate at two distinct layers of the AI ecosystem:

### 1. The Physical Layer: Python Package (`pyparallax`)
A zero-trust execution wrapper that uses Pydantic boundaries and Information Flow Control (IFC) Taint Tracking.

**Installation:**
```bash
pip install -e .
```

**Usage (Hardcoded Guardrails):**
Wrap your LLM tool calls with the `parallax_shield` decorator to strip the agent of the ability to execute unauthorized or tainted actions.
```python
from pyparallax.core import parallax_shield, ClearanceLevel
from pydantic import BaseModel, Field

class DeleteIntent(BaseModel):
    target_path: str = Field(..., description="Absolute path")
    reason: str = Field(..., min_length=10)

@parallax_shield(clearance=ClearanceLevel.SUDO_DESTRUCTIVE, schema=DeleteIntent)
def execute_system_delete(target_path, reason):
    # This function will physically halt if the Agent's context is tainted (IFC) 
    # or if the intent structure fails the Pydantic contract.
    ...
```

### 2. The Cognitive Layer: Vibe Guard Agent Skill (`parallax_vibe_guard`)
A lightweight, silent safety protocol designed to support rapid prototyping. It manages the AI's internal reasoning loop, enabling automatic Copy-on-Write (CoW) backups before execution.

**Installation (Antigravity / Agent IDEs):**
Symlink or copy this repository into your agent's `plugins/` directory (e.g., `~/.gemini/config/plugins/parallax-microshield`). The included `plugin.json` will automatically mount the `SKILL.md` directive into the agent's core instructions.

**Usage (End-User Workflow):**
Once installed, the user does not need to invoke any special commands. The Guard operates silently in the background whenever the AI is prompted.
- **User Prompt:** *"This codebase is a mess, just delete the old UI and make it look like a sleek cyberpunk terminal."*
- **Agent's Internal Action (Intercepted):** Instead of executing `rm -rf src/ui`, the agent is physically bound by the Skill to execute `cp -r src/ui .parallax_trash/1715421000_backup/` first.
- **Agent's Output to User:** *"I've backed up your old UI files to `.parallax_trash` just in case. I've now rewritten the interface into a cyberpunk theme. Feel free to experiment!"*

**Mechanics of the Vibe Guard:**
1. **Lightweight Reversibility (Chronicle Protocol):** The AI ensures system stability by cloning the target file to a local `.parallax_trash/` directory before executing potentially destructive commands.
2. **Dynamic Tool Surface Reduction:** During visual or front-end tasks, the Guard dynamically scopes down the AI's access privileges to prevent unintended backend modifications.
3. **Frictionless Experience:** The system avoids overwhelming the operator with low-level logs, ensuring creative flow is unbroken.

## The Philosophy of the Shield
Robust agentic systems should not rely solely on prompting an LLM to be careful. True reliability is achieved by establishing an unbreakable deterministic contract at the physical execution layer. 

*Parallax trusts the physical signature of the data, ensuring creative freedom is always backed by systemic resilience.*
