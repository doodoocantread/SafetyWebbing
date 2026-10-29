"""Shared test setup.

The hackingBuddy translator and the PentestGPT agent both ship inside their own agent
images (they run in the container, not in the host app), so make those packages
importable for the unit tests that exercise them — without installing the whole
hackingBuddy stack or `unified-agent` (pentestgpt_agent's only non-stdlib dependency,
private and git-pinned; modules that don't touch it, like `plan` and `execution`, import
fine without it — tests that need `agents`/`trace`/`trial` still require it installed).
"""

import sys
from pathlib import Path

_HB_IMAGE = Path(__file__).resolve().parents[1] / "agent_image_hackingbuddy"
if str(_HB_IMAGE) not in sys.path:
    sys.path.insert(0, str(_HB_IMAGE))

_PENTESTGPT_IMAGE = Path(__file__).resolve().parents[1] / "agent_image"
if str(_PENTESTGPT_IMAGE) not in sys.path:
    sys.path.insert(0, str(_PENTESTGPT_IMAGE))
