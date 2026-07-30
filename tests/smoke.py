"""Runs against the built wheel with no dev dependencies, so it uses plain asserts."""

import tempfile
from importlib.metadata import version
from pathlib import Path

from scrubbr.cli import main

MAC = "aa:bb:cc:dd:ee:ff"
SAMPLE = f"host box hw {MAC} up\n"

with tempfile.TemporaryDirectory() as tmp:
    source = Path(tmp) / "log.txt"
    source.write_text(SAMPLE, encoding="utf-8")
    scrubbed = Path(tmp) / "log.clean.txt"

    assert main([str(source), "-o", str(scrubbed), "-y"]) == 0
    text = scrubbed.read_text(encoding="utf-8")
    assert MAC not in text, text

assert version("scrubbr")
print(f"smoke test passed for scrubbr {version('scrubbr')}")
