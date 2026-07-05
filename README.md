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
Symlink or copy this repository into your agent's `plugins/` directory. The included `plugin.json` will automatically mount the `SKILL.md` directive into the agent's core instructions.

**Mechanics of the Vibe Guard:**
1. **Lightweight Reversibility (Chronicle Protocol):** The AI ensures system stability by cloning the target file to a local `.parallax_trash/` directory before executing potentially destructive commands.
2. **Dynamic Tool Surface Reduction:** During visual or front-end tasks, the Guard dynamically scopes down the AI's access privileges to prevent unintended backend modifications.
3. **Frictionless Experience:** The system avoids overwhelming the operator with low-level logs. Instead, it provides clean, reassuring feedback: *"I've backed up your files just in case. Feel free to experiment."*

## The Philosophy of the Shield
Robust agentic systems should not rely solely on prompting an LLM to be careful. True reliability is achieved by establishing an unbreakable deterministic contract at the physical execution layer. 

*Parallax trusts the physical signature of the data, ensuring creative freedom is always backed by systemic resilience.*
