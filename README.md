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
uv tool install git+https://github.com/greenseeing/scrubbr
```

```
pipx install git+https://github.com/greenseeing/scrubbr
```

After that, the `scrubbr` command is available in your terminal.

## How to use it

### Clean up a log file

Say a program wrote a log you want to share. Point scrubbr at the file and tell it where
to save the cleaned copy with `-o`:

```
scrubbr boot-log.txt -o boot-log.clean.txt
```

scrubbr shows you a review of every change it wants to make (see below). Once you approve,
the safe copy lands in `boot-log.clean.txt`, ready to attach or paste. Your original file
is never modified.

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

Without `-o`, scrubbr prints the cleaned text to standard output — the terminal, or
whatever you pipe it into. The report of what was changed always goes to the screen
separately (stderr), so it never mixes into the cleaned text.

### The review step

Before emitting anything, scrubbr shows a diff on your terminal: every line it changed,
original next to replacement, plus a warning list of anything that *looks* sensitive but
that it didn't recognise well enough to rewrite. It then asks:

```
emit scrubbed text? [y/N]
```

Type `y` to approve. Anything else (including just pressing Enter) discards the output —
nothing is printed and no file is written. If you trust a run and want to skip the
question, pass `-y`.

### Options

| Option | What it does |
|---|---|
| `-o FILE`, `--output FILE` | save the cleaned text to `FILE` instead of printing it |
| `-y`, `--no-review` | skip the interactive review |
| `-v`, `--verbose` | list every replaced value: what it was, how often it occurred, what it became |
| `--strict` | refuse to emit anything while suspicious strings remain unscrubbed |
| `--also TEXT` | also scrub this exact string; repeat the flag for several |
| `--no-identity` | don't seed the scanner with this machine's hostname, user and machine-id |

The report normally shows only counts per category. With `-v` it also prints one line per
distinct value — `text=aa:bb:cc:dd:ee:ff count=3 alias=ea:82:db:a4:68:68` — so you can see
exactly what maps to what. Be aware this prints the original sensitive values to your
screen (stderr), so don't share that part.

`--also` is for names only you know are sensitive — an internal server name, a project
codename:

```
scrubbr app.log -o app.clean.txt --also prod-db-07 --also project-nimbus
```

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
  carries a hostname scrubbr cannot guess — pass it explicitly with `--also other-host`.
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
| 4 | the output file given with `-o` could not be written |

For the review, scrubbr opens the controlling terminal (`/dev/tty`) so pipes stay free;
where that device doesn't exist it falls back to your terminal's own input and output, as
long as both are genuinely interactive. Exit 3 only happens when neither is available —
and it exists because the alternative is worse: emitting unreviewed text exactly when the
safety gate could not run. Skipping the review should be your decision, not a fallback.
On any refusal, `-o` writes nothing — the output file is only created after you approve.
