#!/usr/bin/env python3
"""compat/install-binds.py: the marked block in ~/.config/hypr/bindings.lua.

The plugin was ai.kub0.vallum through 0.4.6. A block written then binds keys
to a plugin that no longer exists, so writing the block for ai.kub0.agent has
to take the old one out: left in, the same keys are bound twice and the first
bind opens nothing.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "compat" / "install-binds.py"
NEW = "ai.kub0.agent"
OLD = "ai.kub0.vallum"
NEW_LINE = 'o.bind("SUPER + SHIFT + ALT + S", "kub0", "omarchy-shell shell toggle ai.kub0.agent \'{}\'")'
OLD_BLOCK = (
    "-- BEGIN ai.kub0.vallum\n"
    'o.bind("SUPER + SHIFT + ALT + S", "Vallum", "omarchy-shell shell toggle ai.kub0.vallum \'{}\'")\n'
    "-- END ai.kub0.vallum\n"
)
MINE = 'o.bind("SUPER + RETURN", "Terminal", "ghostty")\n'
AFTER = 'o.bind("SUPER + B", "Browser", "firefox")\n'


def run(config: Path, plugin_id: str, block: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, XDG_CONFIG_HOME=str(config))
    return subprocess.run(
        [sys.executable, str(SCRIPT), plugin_id, block], env=env, capture_output=True, text=True, timeout=30
    )


def bindings(config: Path) -> Path:
    return config / "hypr" / "bindings.lua"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="kub0-binds-") as td:
        # 1. no file yet: the block is the file
        config = Path(td) / "fresh"
        r = run(config, NEW, NEW_LINE)
        assert r.returncode == 0 and r.stdout.strip() == "ok", (r.returncode, r.stdout, r.stderr)
        text = bindings(config).read_text()
        assert text.count(f"-- BEGIN {NEW}") == 1 and text.count(f"-- END {NEW}") == 1, text
        assert NEW_LINE in text, text

        # 2. written again: replaced, not added a second time
        r = run(config, NEW, NEW_LINE.replace("SHIFT + ALT", "ALT"))
        assert r.returncode == 0, r.stderr
        text = bindings(config).read_text()
        assert text.count(f"-- BEGIN {NEW}") == 1, text
        assert "SUPER + ALT + S" in text and "SUPER + SHIFT + ALT + S" not in text, text

        # 3. the old id's block, between the user's own lines: it goes, they stay
        config = Path(td) / "upgraded"
        (config / "hypr").mkdir(parents=True)
        bindings(config).write_text(MINE + "\n" + OLD_BLOCK + "\n" + AFTER)
        r = run(config, NEW, NEW_LINE)
        assert r.returncode == 0, r.stderr
        text = bindings(config).read_text()
        assert OLD not in text, "the old block is still there:\n" + text
        assert "Vallum" not in text, text
        assert text.count(f"-- BEGIN {NEW}") == 1 and NEW_LINE in text, text
        assert MINE in text and AFTER in text, "a line of the user's own was lost:\n" + text
        assert text.count("SUPER + SHIFT + ALT + S") == 1, "the keys are bound once:\n" + text

        # 4. both blocks there (a hand merge): one current block is left
        config = Path(td) / "both"
        (config / "hypr").mkdir(parents=True)
        bindings(config).write_text(OLD_BLOCK + "\n" + f"-- BEGIN {NEW}\n{NEW_LINE}\n-- END {NEW}\n" + AFTER)
        r = run(config, NEW, NEW_LINE)
        assert r.returncode == 0, r.stderr
        text = bindings(config).read_text()
        assert OLD not in text and text.count(f"-- BEGIN {NEW}") == 1 and AFTER in text, text

        # 5. another plugin's write never touches a block that is not its own
        config = Path(td) / "other"
        (config / "hypr").mkdir(parents=True)
        bindings(config).write_text(OLD_BLOCK)
        r = run(config, "com.example.other", 'o.bind("SUPER + O", "Other", "other")')
        assert r.returncode == 0, r.stderr
        text = bindings(config).read_text()
        assert OLD_BLOCK in text and "-- BEGIN com.example.other" in text, text

        # 6. a symlinked bindings.lua is refused and left alone
        config = Path(td) / "link"
        (config / "hypr").mkdir(parents=True)
        target = Path(td) / "elsewhere.lua"
        target.write_text(MINE)
        bindings(config).symlink_to(target)
        r = run(config, NEW, NEW_LINE)
        assert r.returncode != 0, "a symlink was written through"
        assert target.read_text() == MINE, target.read_text()

    print("install-binds: 6 cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
