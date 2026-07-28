import random
import string

import pytest

from scrubbr import LocalIdentity, scrub

ALPHABET = string.printable + "::::----....$$$@@@"

FRAGMENTS = (
    "-----BEGIN X-----",
    "-----END X-----",
    "$6$a$b",
    "eyJa.b.c",
    "fe80::",
    "aa:bb:cc:dd:ee:ff",
    "0x",
    "::",
    "ssid=",
    "psk=",
    "/home/",
    "/dev/disk/by-id/",
    "2001:db8::",
    "999.999.999.999",
    "ff:ff",
    "1:2:3:4:5:6:7:8:9:10",
    "\x00",
    "😀",
)


def _noise(rng: random.Random) -> str:
    return "".join(
        rng.choice(FRAGMENTS) if rng.random() < 0.4 else rng.choice(ALPHABET)
        for _ in range(rng.randint(0, 40))
    )


@pytest.mark.parametrize("seed", range(400))
def test_malformed_input_never_raises(seed: int) -> None:
    # This runs as a filter in a pipe: an exception loses whatever the user piped in.
    rng = random.Random(seed)
    scrub(_noise(rng), LocalIdentity(hostname="h", username="u"))


def test_empty_input_is_handled() -> None:
    result = scrub("")
    assert result.text == ""
    assert result.findings == []


def test_text_with_no_trailing_newline_is_preserved() -> None:
    assert scrub("no newline here").text == "no newline here"
