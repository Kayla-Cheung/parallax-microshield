# Parallax Microshield 🛡️

*A Lightweight, Zero-Trust Defense Matrix for Vibe-Coding AI Agents.*

## The Sociological Premise
In the era of "Vibe Coding," non-technical operators grant AI models full execution rights with zero engineering awareness. They blindly click "Approve" on destructive commands, operating entirely on aesthetics ("make it pop") rather than deterministic system logic. This creates a fatal **Cognitive-Executive Coupling**, where hallucinatory AI intent translates instantly into irreversible OS-level destruction. 

**Parallax Microshield** physically decouples AI cognition from OS execution. It assumes the AI is inherently volatile and the human operator is inherently blind.

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
A lightweight, silent prompt-injection protocol designed to protect "Vibe Coders." It overrides the AI's internal reasoning loop, forcing it to implement Copy-on-Write (CoW) backups before any execution.

**Installation (Antigravity / Agent IDEs):**
Symlink or copy this repository into your agent's `plugins/` directory. The included `plugin.json` will automatically mount the `SKILL.md` directive into the agent's subconscious.

**Mechanics of the Vibe Guard:**
1. **Lightweight Reversibility (Chronicle Protocol):** The AI is physically forbidden from destructive execution (e.g., `rm -rf`) without first cloning the target file to a local `.parallax_trash/` directory.
2. **Dynamic Tool Surface Reduction:** If the human operator issues a purely visual/UI request ("make the button red"), the Guard dynamically revokes the AI's access to the backend shell.
3. **Silent Intervention:** The Agent is strictly forbidden from explaining "Cognitive-Executive Separation" to the user. It simply states: *"I've backed up your files just in case. Feel free to experiment."*

## The Philosophy of the Shield
True safety in agentic systems isn't achieved by begging a Large Language Model to be careful. It is achieved by assuming the LLM is already compromised and wrapping the execution layer in an unbreakable deterministic contract. 

*No matter how convincing the Agent's reasoning is, Parallax only trusts the physical signature of the data.*
