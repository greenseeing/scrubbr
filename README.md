# scrubbr

Sanitize Linux diagnostics before pasting them into an LLM chat.

When you ask an AI assistant for help with a system problem, you usually paste in logs —
and logs are full of things that identify you: your username, your hostname, your Wi-Fi
network name, hardware addresses, sometimes even keys and passwords. scrubbr replaces all
of that with harmless random look-alikes, shows you exactly what it changed, and only then
hands the text over.

The same value always gets the same replacement, so the log still makes sense: if your
laptop appears forty times, it becomes `host-a` all forty times, and the assistant can
still follow what happened.

## Install

You need Python 3.13 or newer. Then, with either [uv](https://docs.astral.sh/uv/) or
[pipx](https://pipx.pypa.io/):

```
uv tool install scrubbr
```

```
pipx install scrubbr
```

After that, the `scrubbr` command is available in your terminal, and `scrubbr --version`
tells you which release you have.

To run unreleased changes, install from the repository instead:

```
uv tool install git+https://github.com/greenseeing/scrubbr
```

## Updating

```
uv tool upgrade scrubbr
```

or `pipx upgrade scrubbr`. [CHANGELOG.md](CHANGELOG.md) lists what changed in each release.

A git install is a moving branch rather than a version, so there is nothing for `upgrade` to
compare against; reinstall it instead:

```
uv tool install --force git+https://github.com/greenseeing/scrubbr
```

## How to use it

### Clean up a log file

Say a program wrote a log you want to share. Point scrubbr at the file:

```
scrubbr boot-log.txt
```

scrubbr shows you a review of every change it wants to make (see below). Once you approve,
the safe copy lands in `boot-log.scrubbed.txt` next to the original, ready to attach or
paste — the review screen shows the destination and lets you change it, or pick your own
up front with `-o`:

```
scrubbr boot-log.txt -o boot-log.clean.txt
```

Your original file is never modified. If the destination file already exists, it is
overwritten.

### Clean up a command's output

You can also feed scrubbr the output of another command directly, using a pipe (`|`):

```
dmesg | scrubbr -o dmesg.clean.txt
journalctl -u NetworkManager -n 200 | scrubbr -o nm.clean.txt
```

The pipe sends whatever the first command prints straight into scrubbr, so nothing
sensitive ever touches your disk unscrubbed.

### Straight to the clipboard

If you'd rather skip the file entirely, pipe scrubbr's output into your clipboard tool and
paste it into the chat:

```
journalctl -u NetworkManager -n 200 | scrubbr | wl-copy
```

(`wl-copy` is for Wayland desktops; on X11 use `xclip -selection clipboard`.)

Without `-o`, scrubbr prints the cleaned text to standard output whenever that output is
a pipe or a redirection. When standard output is your terminal, it writes a file instead —
`NAME.scrubbed.EXT` next to the input (`scrubbed.txt` for piped input) — so the cleaned
text never floods your screen. The report of what was changed always goes to the screen
separately (stderr), so it never mixes into the cleaned text. If you redirect stderr too
(so it isn't a terminal), the report switches to JSON lines — one event per line — so
scripts can parse it.

### The review step

Before emitting anything, scrubbr opens a full-screen review on your terminal: a table
with one row per distinct value it wants to replace — its category, how often it occurs,
and what it will become. Anything that *looks* sensitive but that scrubbr didn't
recognise well enough to rewrite is listed too, as a `warn` row. From there:

| Key | What it does |
|---|---|
| `space` | keep the selected value as it is (press again to scrub it after all); on a `warn` row, scrub that text too |
| `a` | scrub additional text — type to fuzzy-find any token from the input, or enter an exact string |
| `r` | choose the selected value's replacement: the minted alias, `[REDACTED]`, or something you type |
| `y` | show the full diff; `y` again emits, `Escape` goes back to the table |
| `e` | on the diff — edit the destination path shown at the top; `Enter` returns to the diff |
| `q` | abort — nothing is printed and no file is written |

When the cleaned text is headed for a file rather than a pipe, the diff screen shows the
destination path at the top; press `e` to change it before confirming.

Every change re-runs the scrubber, so a value you keep is restored at every occurrence
and text you add is replaced at every occurrence, with the report and warnings kept
honest throughout.

With `--plain` — or on a terminal too limited for the full screen — you get the classic
prompt instead: the diff, the warning list, and one question:

```
write scrubbed text to boot-log.scrubbed.txt? [y/N]
```

(or `emit scrubbed text? [y/N]` when the output is going to a pipe). Type `y` to approve.
Anything else (including just pressing Enter) discards the output.
If you trust a run and want to skip the review entirely, pass `-y`.

### Options

| Option | What it does |
|---|---|
| `-o FILE`, `--output FILE` | save the cleaned text to `FILE` — overrides both stdout and the derived `NAME.scrubbed.EXT` default |
| `-y`, `--no-review` | skip the interactive review |
| `--plain` | review with the classic y/N prompt instead of the full-screen interface |
| `-v`, `--verbose` | list every replaced value: what it was, how often it occurred, what it became |
| `--strict` | refuse to emit anything while suspicious strings remain unscrubbed |
| `--also TEXT` | also scrub this exact string; repeat the flag for several. IPs, long hex, UUIDs and emails keep their shape (IPs are replaced even when private or loopback); names become `[REDACTED]` |
| `--no-identity` | don't seed the scanner with this machine's hostname, user and machine-id |
| `--version` | print the installed version and exit |

The report normally shows only counts per category. With `-v` it also prints a table with
one row per distinct value, so you can see exactly what maps to what:

```
kind   count  text                alias
mac        3  aa:bb:cc:dd:ee:ff   ea:82:db:a4:68:68
email      1  alice@corp.example  person-a@example.invalid
```

The table is sized to your window; values too long for their column are shortened in the
middle (`9f2a1c7b…4c6b`). Be aware this prints the original sensitive values to your
screen (stderr), so don't share that part.

`--also` is for values only you know are sensitive — an internal server name, a project
codename, an address inside your own network:

```
scrubbr app.log -o app.clean.txt --also prod-db-07 --also 10.1.2.7
```

Each value's type is detected from its shape. An IP address, hex of 32+ characters, a UUID
or an email is replaced the same way scrubbr replaces ones it finds on its own — same
shape, same alias pool — and a declared IP is replaced even if it is private or loopback,
which incidental matches are not. A value with no recognisable shape (a name) becomes
`[REDACTED]`; note that every such name renders identically, so two declared names cannot
be told apart in the output.

## What it replaces

| | |
|---|---|
| Hardware | MAC and Bluetooth addresses, disk WWN / `by-id` paths |
| Network | public IPv4 and IPv6, SSIDs, BSSIDs |
| Identity | this machine's hostname, your username, `/home/<user>`, machine-id, emails |
| Secrets | PEM blocks, `openssl passwd` hashes, JWTs, `psk=`/`password=` values, hex ≥32 chars |
| Other | UUIDs, certificate fingerprints |

Replacements keep the original's shape: `AA-BB-CC-DD-EE-FF` stays hyphenated and uppercase,
a v4 UUID stays a valid v4 UUID, public IPs become RFC 5737 documentation addresses. Names
become readable aliases (`host-a`, `user-a`, `network-a`) because `host-a can't reach host-b`
is diagnosable and two random hex blobs are not.

Generated MACs are always locally-administered unicast (second hex digit `2`, `6`, `a`, `e`),
which is what macchanger, systemd-networkd and Android all produce — and which makes it
impossible to accidentally mint a broadcast or reserved multicast address.

## What it deliberately leaves alone

`127.0.0.1`, `::1`, `0.0.0.0`, RFC1918 private ranges, reserved MACs (broadcast, IPv4/IPv6
multicast, STP, VRRP), standard system paths, and system usernames like `root`. These
identify nobody and carry diagnostic meaning; scrubbing them would hand the LLM a log it
cannot reason about.

## Trust

Regex scrubbing has false negatives, and the failure mode is silent. Two mitigations:

- Anything left over that looks sensitive is **reported, not rewritten**, with a line
  number: high entropy, a known credential prefix like `ghp_` or `AKIA`, or colon-hex that
  is recognisably structured but is neither a MAC, a fingerprint nor a valid address. The
  tool tells you where it is unsure rather than implying it caught everything.
- Every run shows an interactive diff on your terminal before emitting. Skip it with `-y`.

`--strict` refuses to emit at all while anything suspicious remains unscrubbed.

## Known limits

- Hostnames are found by asking *this* system for its own name. A log from another machine
  carries a hostname scrubbr cannot guess — pass it explicitly with `--also other-host`
  (it will appear as `[REDACTED]`).
- `--also` matches the exact spelling you give it. For IPv6 that means `--also fe80::1`
  also covers `FE80::1` but not the longhand `fe80:0:0:0:0:0:0:1` — declare each spelling
  the log uses.
- Hex of 32+ characters is replaced with no exceptions, so checksums and 40-character git
  SHAs get scrambled too. That is deliberate: no special cases means nothing slips through.
- Replacements are per-run. Sanitizing the same file twice gives different output; sanitize
  once and keep the result if you need two pastes to line up.

Also worth knowing: don't use `journalctl -x` for output you intend to share. The
explanatory text it adds widens what gets exposed, and no scrubber can help with data you
chose to include.

## Exit codes

For scripts and the curious:

| Exit | Meaning |
|---|---|
| 0 | scrubbed text emitted |
| 1 | you declined at the review |
| 2 | refused under `--strict` because suspicious strings remained |
| 3 | refused because there was no terminal to review on — pass `-y` to skip review |
| 4 | the output file could not be written |

For the review, scrubbr opens the controlling terminal (`/dev/tty`) so pipes stay free;
where that device doesn't exist it falls back to your terminal's own input and output, as
long as both are genuinely interactive. Exit 3 only happens when neither is available —
and it exists because the alternative is worse: emitting unreviewed text exactly when the
safety gate could not run. Skipping the review should be your decision, not a fallback.
On any refusal, no output file is written — whether named with `-o` or derived — because
the file is only created after you approve.

## Releasing

For maintainers. Bump the version:

```
uv version --bump patch
```

Move the entries under `## [Unreleased]` in `CHANGELOG.md` into a section for the new
version, commit both files, then tag:

```
git tag v0.2.1 && git push origin main --tags
```

The tag triggers `.github/workflows/release.yml`, which builds the wheel and source archive,
smoke-tests both in an isolated environment, publishes to PyPI using trusted publishing — no
API token is stored anywhere — and then opens a GitHub release for the tag, with notes taken
from that version's section of the changelog and both artifacts attached.

It refuses to publish if the tag and the version in `pyproject.toml` disagree, because a PyPI
version can never be replaced once uploaded. The upload itself skips files the index already
has, so a run that fails partway can be re-run safely.
