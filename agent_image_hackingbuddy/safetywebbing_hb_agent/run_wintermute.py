"""The claude_oauth entry point: install the Claude Code bridge, then run hackingBuddyGPT's
own ``wintermute`` CLI in-process.

``claude_bridge.install()`` monkey-patches ``LiteLLM.raw_completion`` on the class, so it
has to run in the SAME process as hackingBuddyGPT, before ``wintermute``'s own ``main()``
parses arguments and instantiates the use-case. ``cli.py`` therefore execs this module
(``python -m safetywebbing_hb_agent.run_wintermute ...``) instead of the ``wintermute``
console script for that one LLM path; the argv it is given is otherwise identical (see
``cli.py::_build_wintermute_cmd``), so this file is a thin shim, not a reimplementation.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> None:
    from safetywebbing_hb_agent.claude_bridge import install

    install()

    from hackingBuddyGPT.cli.wintermute import main as wintermute_main

    sys.argv = ["wintermute", *(sys.argv[1:] if argv is None else argv)]
    wintermute_main()


if __name__ == "__main__":
    main()
