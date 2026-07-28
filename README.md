# scrubbr

Sanitize Linux diagnostics before pasting them into an LLM chat.

```
journalctl -u NetworkManager -n 200 | scrubbr | wl-copy
```

Reads text, replaces everything that identifies you with random look-alikes of the same
shape, writes the clean text to stdout and a report to stderr. The same value always gets
the same replacement, so the log still correlates and stays diagnosable.

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
- Every run shows an interactive diff on `/dev/tty` before emitting. Skip it with `-y`.

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

## Install

```
uv tool install git+https://github.com/greenseeing/scrubbr
```

or `pipx install git+https://github.com/greenseeing/scrubbr`. Python 3.13+.

## Usage

```
scrubbr [file] [-y] [--strict] [--no-identity] [--also TEXT]
```

Reads stdin when no file is given.

| Exit | Meaning |
|---|---|
| 0 | scrubbed text emitted |
| 1 | you declined at the review |
| 2 | refused under `--strict` because suspicious strings remained |
| 3 | refused because there was no terminal to review on — pass `-y` to skip review |

Exit 3 exists because the alternative is worse: emitting unreviewed text exactly when the
safety gate could not run. Skipping the review should be your decision, not a fallback.
