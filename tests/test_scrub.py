import random
import re

import pytest

from scrubbr import AliasBook, Kind, LocalIdentity, scrub
from scrubbr.shapes import RESERVED_MAC_PREFIXES

JOURNAL = """\
Jun 17 22:20:36 dev-thinkpad wpa_supplicant[991]: wlan0: SME: Trying to authenticate with 84:0b:bb:77:08:38 (SSID='Hartley-House-5G' freq=2462 MHz)
Jun 17 22:20:37 dev-thinkpad NetworkManager[1024]: <info> device (wlan0): supplicant state: disconnected
Jun 17 22:20:38 dev-thinkpad kernel: wlan0: associated with aa:bb:cc:dd:ee:ff
Jun 17 22:20:39 dev-thinkpad systemd[1]: Started User Manager for UID 1000
Jun 17 22:20:40 dev-thinkpad app[2048]: loading /home/dev/.config/app/settings.toml
Jun 17 22:20:41 dev-thinkpad app[2048]: session 550e8400-e29b-41d4-a716-446655440000 opened
Jun 17 22:20:42 dev-thinkpad app[2048]: peer aa:bb:cc:dd:ee:ff responded from 81.2.69.142
Jun 17 22:20:43 dev-thinkpad app[2048]: psk = 9f2a1c7b4e6d8a0f3c5b7d9e1a2f4c6b8d0e2a4c6b8d0f1e3a5c7b9d0e2f4a6c
Jun 17 22:20:44 dev-thinkpad app[2048]: bound to 127.0.0.1 reading /etc/fstab
"""


def scrubbed(text: str, **kw: object) -> str:
    return scrub(text, **kw).text  # type: ignore[arg-type]


class TestNothingLeaks:
    def test_no_sensitive_value_survives_anywhere_in_output(self) -> None:
        secrets_present = [
            "84:0b:bb:77:08:38",
            "aa:bb:cc:dd:ee:ff",
            "Hartley-House-5G",
            "dev-thinkpad",
            "/home/dev",
            "550e8400-e29b-41d4-a716-446655440000",
            "81.2.69.142",
            "9f2a1c7b4e6d8a0f3c5b7d9e1a2f4c6b8d0e2a4c6b8d0f1e3a5c7b9d0e2f4a6c",
        ]
        out = scrubbed(JOURNAL, identity=LocalIdentity(hostname="dev-thinkpad", username="dev"))
        for value in secrets_present:
            assert value not in out, f"{value!r} leaked into the output"

    def test_pem_body_never_survives(self) -> None:
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
            "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
            "-----END PRIVATE KEY-----\n"
        )
        out = scrubbed(pem)
        assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj" not in out
        assert "PRIVATE KEY" in out, "the fact that a private key was present is worth keeping"


class TestMacInvariants:
    @pytest.mark.parametrize("run", range(200))
    def test_minted_macs_are_locally_administered_unicast(self, run: int) -> None:
        out = scrubbed(f"mac {run:02x}:11:22:33:44:55")
        mac = re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", out)
        assert mac is not None
        assert mac.group()[1] in "26ae", f"{mac.group()} is not locally administered unicast"

    def test_minted_macs_are_never_reserved(self) -> None:
        for i in range(200):
            out = scrubbed(f"mac {i:02x}:11:22:33:44:66")
            mac = re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", out)
            assert mac is not None
            assert not mac.group().replace(":", "").startswith(RESERVED_MAC_PREFIXES)
            assert mac.group() != "00:00:00:00:00:00"

    def test_reserved_macs_are_left_alone(self) -> None:
        text = "bcast ff:ff:ff:ff:ff:ff v4mcast 01:00:5e:00:00:01 v6mcast 33:33:00:00:00:01 stp 01:80:c2:00:00:00 vrrp 00:00:5e:00:01:01 cdp 01:00:0c:cc:cc:cc"
        assert scrubbed(text) == text


class TestConsistency:
    def test_one_value_yields_one_alias_everywhere(self) -> None:
        out = scrubbed("a aa:bb:cc:dd:ee:ff b aa:bb:cc:dd:ee:ff c aa:bb:cc:dd:ee:ff")
        found = re.findall(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", out)
        assert len(found) == 3
        assert len(set(found)) == 1, "the same MAC must map to the same alias every time"

    def test_distinct_values_yield_distinct_aliases(self) -> None:
        out = scrubbed("aa:bb:cc:dd:ee:ff and 11:22:33:44:55:66")
        found = re.findall(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", out)
        assert len(set(found)) == 2

    def test_separator_and_case_are_preserved(self) -> None:
        assert re.search(r"(?:[0-9A-F]{2}-){5}[0-9A-F]{2}", scrubbed("AA-BB-CC-DD-EE-FF"))
        assert re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", scrubbed("aa:bb:cc:dd:ee:ff"))
        assert re.search(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", scrubbed("aabb.ccdd.eeff"))

    def test_the_same_ipv6_in_two_cases_shares_one_alias(self) -> None:
        out = scrubbed("a 2a00:1450:4009:80f::200e b 2A00:1450:4009:80F::200E")
        found = re.findall(r"2001:db8::[0-9a-f]+", out)
        assert len(found) == 2
        assert len(set(found)) == 1, "case must not split one address into two aliases"

    def test_repeated_value_findings_share_one_alias_and_it_is_not_the_original(self) -> None:
        result = scrub("a aa:bb:cc:dd:ee:ff b aa:bb:cc:dd:ee:ff")
        mac_findings = [f for f in result.findings if f.kind == Kind.MAC]
        assert len(mac_findings) == 2
        assert mac_findings[0].alias == mac_findings[1].alias
        assert mac_findings[0].alias != "aa:bb:cc:dd:ee:ff"


class TestColonHexCollisions:
    def test_compressed_ipv6_tail_is_not_mistaken_for_a_mac(self) -> None:
        result = scrub("addr fe80::aa:bb:cc:dd:ee:ff")
        assert Kind.MAC not in {f.kind for f in result.findings}

    def test_fingerprint_is_not_mistaken_for_a_mac(self) -> None:
        fp = ":".join(f"{b:02X}" for b in range(32))
        result = scrub(f"SHA256 Fingerprint={fp}")
        assert Kind.MAC not in {f.kind for f in result.findings}
        assert fp not in result.text

    def test_eight_group_ipv6_is_not_mistaken_for_a_mac(self) -> None:
        result = scrub("addr 11:22:33:44:55:66:77:88")
        assert Kind.MAC not in {f.kind for f in result.findings}

    def test_real_mac_next_to_punctuation_is_still_found(self) -> None:
        result = scrub("(aa:bb:cc:dd:ee:ff),")
        assert Kind.MAC in {f.kind for f in result.findings}

    @pytest.mark.parametrize(
        "text",
        [
            "device aa:bb:cc:dd:ee:ff.",
            'hw "aa:bb:cc:dd:ee:ff"',
            "[aa:bb:cc:dd:ee:ff]",
            "x,aa:bb:cc:dd:ee:ff,y",
            "mac=aa:bb:cc:dd:ee:ff",
            "wlan0/aa:bb:cc:dd:ee:ff",
            "aa:bb:cc:dd:ee:ff is up",
            "hw\taa:bb:cc:dd:ee:ff\tup",
            "<aa:bb:cc:dd:ee:ff>",
            "AA-BB-CC-DD-EE-FF.",
        ],
    )
    def test_a_mac_is_found_whatever_punctuation_surrounds_it(self, text: str) -> None:
        # A MAC ending a sentence used to be invisible, which is a silent leak: the
        # lookahead excluded a dot, and logs write "associated with aa:bb:cc:dd:ee:ff."
        assert "aa:bb:cc:dd:ee:ff" not in scrub(text).text.lower()

    def test_dotted_notation_is_still_fenced_against_longer_hex_runs(self) -> None:
        result = scrub("id aabb.ccdd.eeff.1122")
        assert Kind.MAC not in {f.kind for f in result.findings}

    def test_dotted_notation_ending_a_sentence_is_found(self) -> None:
        assert "aabb.ccdd.eeff" not in scrub("hw aabb.ccdd.eeff.").text


class TestBareMac:
    def test_bare_twelve_hex_is_scrubbed_when_labelled(self) -> None:
        for text in ("mac aabbccddeeff", "hwaddr=aabbccddeeff", "BSSID: aabbccddeeff"):
            assert "aabbccddeeff" not in scrub(text).text, text

    def test_bare_twelve_hex_is_left_alone_without_a_label(self) -> None:
        # Indistinguishable from a truncated hash; scrubbing every 12-hex run would
        # scramble ordinary identifiers throughout the log.
        text = "commit aabbccddeeff landed"
        assert scrub(text).text == text


class TestEui64LinkLocal:
    def test_link_local_iid_resolves_to_the_same_alias_as_the_bare_mac(self) -> None:
        out = scrubbed("link fe80::0a00:27ff:fe12:3456 hw 08:00:27:12:34:56")
        assert "0a00:27ff:fe12:3456" not in out
        assert "08:00:27:12:34:56" not in out
        mac = re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", out)
        assert mac is not None
        octets = mac.group().split(":")
        flipped = f"{int(octets[0], 16) ^ 0x02:02x}"
        embedded = f"{flipped}{octets[1]}:{octets[2]}ff:fe{octets[3]}:{octets[4]}{octets[5]}"
        assert embedded in out, "the EUI-64 IID must carry the same alias as the bare MAC"


class TestAllowlist:
    def test_non_identifying_values_survive(self) -> None:
        text = "bound 127.0.0.1 and ::1 and 0.0.0.0 and 192.168.1.1 reading /etc/fstab as root"
        assert scrubbed(text) == text

    def test_public_ip_is_replaced_with_a_documentation_address(self) -> None:
        out = scrubbed("peer 81.2.69.142")
        assert "81.2.69.142" not in out
        assert re.search(r"(?:203\.0\.113|198\.51\.100|192\.0\.2)\.\d+", out)


class TestExtraLiterals:
    def test_an_extra_hex_value_is_replaced_shape_preservingly_not_as_a_hostname(self) -> None:
        value = "AB" * 16
        out = scrubbed(f"id {value}", identity=LocalIdentity(extra=(value,)))
        assert value not in out
        assert re.search(r"id [0-9A-F]{32}", out)
        assert "host-" not in out
        assert "[REDACTED]" not in out

    def test_the_machine_id_in_extra_is_scrubbed_as_hex_not_as_a_hostname(self) -> None:
        machine_id = "3f2a1c7b4e6d8a0f3c5b7d9e1a2f4c6b"
        out = scrubbed(f"id {machine_id}", identity=LocalIdentity(extra=(machine_id,)))
        assert machine_id not in out
        assert re.search(r"id [0-9a-f]{32}", out)
        assert "host-" not in out

    def test_an_extra_private_ipv4_is_scrubbed_while_other_private_addresses_survive(self) -> None:
        out = scrubbed(
            "bound 192.168.1.7 and 192.168.1.8",
            identity=LocalIdentity(extra=("192.168.1.7",)),
        )
        assert "192.168.1.7" not in out
        assert "192.168.1.8" in out, "only the declared address may be forced past the allowlist"
        assert re.search(r"(?:203\.0\.113|198\.51\.100|192\.0\.2)\.\d+", out)

    def test_an_extra_loopback_ipv4_is_scrubbed_even_though_loopback_is_normally_kept(self) -> None:
        out = scrubbed("bound 127.0.0.1 now", identity=LocalIdentity(extra=("127.0.0.1",)))
        assert "127.0.0.1" not in out
        assert re.search(r"(?:203\.0\.113|198\.51\.100|192\.0\.2)\.\d+", out)

    @pytest.mark.parametrize("address", ["fe80::1", "::1"])
    def test_an_extra_kept_ipv6_address_is_scrubbed(self, address: str) -> None:
        out = scrubbed(f"addr {address} up", identity=LocalIdentity(extra=(address,)))
        assert f" {address} " not in out
        assert "2001:db8::" in out

    def test_an_extra_ipv6_is_forced_whatever_case_the_log_uses(self) -> None:
        out = scrubbed("addr fe80::1 up", identity=LocalIdentity(extra=("FE80::1",)))
        assert "fe80::1" not in out
        assert "2001:db8::" in out

    def test_a_forced_link_local_with_an_embedded_mac_still_correlates_with_the_bare_mac(
        self,
    ) -> None:
        # Forcing may only flip keep decisions, never change how an address is scrubbed:
        # the declared link-local must still resolve to the same alias as its bare MAC.
        address = "fe80::0a00:27ff:fe12:3456"
        out = scrubbed(
            f"link {address} hw 08:00:27:12:34:56",
            identity=LocalIdentity(extra=(address,)),
        )
        assert "0a00:27ff:fe12:3456" not in out
        assert "08:00:27:12:34:56" not in out
        mac = re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", out)
        assert mac is not None
        octets = mac.group().split(":")
        flipped = f"{int(octets[0], 16) ^ 0x02:02x}"
        embedded = f"{flipped}{octets[1]}:{octets[2]}ff:fe{octets[3]}:{octets[4]}{octets[5]}"
        assert embedded in out

    def test_an_extra_name_becomes_redacted(self) -> None:
        result = scrub(
            "connecting to prod-db-07 now", identity=LocalIdentity(extra=("prod-db-07",))
        )
        assert "prod-db-07" not in result.text
        assert "[REDACTED]" in result.text
        assert result.counts[Kind.REDACTED] == 1

    def test_every_extra_name_becomes_redacted_with_no_correlation_between_them(self) -> None:
        out = scrubbed(
            "alice pinged prod-db-07",
            identity=LocalIdentity(extra=("alice", "prod-db-07")),
        )
        assert "alice" not in out
        assert "prod-db-07" not in out
        assert out.count("[REDACTED]") == 2

    def test_an_extra_uuid_keeps_the_uuid_kind(self) -> None:
        value = "550e8400-e29b-41d4-a716-446655440000"
        result = scrub(f"session {value}", identity=LocalIdentity(extra=(value,)))
        assert value not in result.text
        assert "[REDACTED]" not in result.text
        assert {f.kind for f in result.findings} == {Kind.UUID}


class TestUuid:
    def test_version_and_variant_are_preserved(self) -> None:
        out = scrubbed("id 550e8400-e29b-41d4-a716-446655440000")
        new = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", out)
        assert new is not None
        assert new.group()[14] == "4", "version nibble must stay 4"
        assert new.group()[19] in "89ab", "variant nibble must stay RFC 9562"

    def test_v1_uuid_stays_v1_and_loses_its_embedded_mac(self) -> None:
        out = scrubbed("id f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
        new = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", out)
        assert new is not None
        assert new.group()[14] == "1"
        assert "00a0c91e6bf6" not in out


class TestHex:
    def test_hex_of_32_or_more_is_scrubbed(self) -> None:
        value = "9f" * 16
        out = scrubbed(f"key={value}")
        assert value not in out
        assert re.search(r"key=[0-9a-f]{32}", out)

    def test_hex_below_32_is_left_alone(self) -> None:
        text = "colour #ff0000 const 0xdeadbeef short a1b2c3d"
        assert scrubbed(text) == text

    def test_hex_case_and_length_are_preserved(self) -> None:
        out = scrubbed("K=" + "AB" * 20)
        assert re.search(r"K=[0-9A-F]{40}\b", out)

    def test_hex_behind_an_0x_prefix_is_still_scrubbed(self) -> None:
        value = "de" * 20
        out = scrubbed(f"addr 0x{value}")
        assert value not in out
        assert re.search(r"0x[0-9a-f]{40}", out), "the 0x prefix must survive"


class TestGlobalIpv6:
    def test_global_address_carrying_a_mac_is_aliased_whole(self) -> None:
        # A routable prefix identifies the network it was delegated to, so preserving it
        # while rewriting only the interface identifier would leak the more useful half.
        out = scrubbed("addr 2001:470:1f0b:1234:0a00:27ff:fe12:3456")
        assert "2001:470:1f0b:1234" not in out
        assert "0a00:27ff:fe12:3456" not in out
        assert not out.strip().endswith("fe80::4c91:07ff:feb2:3cd8")

    def test_link_local_without_a_hardware_identifier_is_kept(self) -> None:
        text = "addr fe80::1"
        assert scrubbed(text) == text


class TestResidualRisk:
    def test_unmatched_high_entropy_token_is_reported_not_scrubbed(self) -> None:
        result = scrub("token ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
        assert result.residuals, "a credential-shaped token must be reported"
        assert any("ghp_" in r.text for r in result.residuals)

    def test_clean_text_reports_no_residuals(self) -> None:
        result = scrub("nothing to see here, just ordinary words\n")
        assert result.residuals == []

    def test_the_tool_never_warns_about_its_own_replacements(self) -> None:
        # Aliases are high-entropy by construction, so without excluding them the tool
        # warns about its own output every run and the warning stops meaning anything.
        result = scrub(JOURNAL, identity=LocalIdentity(hostname="dev-thinkpad", username="dev"))
        minted = {f.text for f in result.findings}
        for residual in result.residuals:
            assert residual.text not in minted
        assert not [r for r in result.residuals if r.reason == "high entropy"], (
            f"warned about its own aliases: {[r.text for r in result.residuals]}"
        )


class TestReviewRegressions:
    def test_pem_with_an_unexpected_character_still_loses_its_body(self) -> None:
        # Narrowing the body to the base64 alphabet made one stray character fail the
        # whole block and pass the key through verbatim.
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
        for oddity in ("#comment", "Proc-Type: 4,ENCRYPTED", "; note", "(x)"):
            pem = f"-----BEGIN RSA PRIVATE KEY-----\n{oddity}\n{body}\n-----END RSA PRIVATE KEY-----\n"
            assert body not in scrubbed(pem), f"key survived alongside {oddity!r}"

    def test_a_username_does_not_strip_an_email_down_to_its_domain(self) -> None:
        out = scrubbed("contact dev@example.com", identity=LocalIdentity(username="dev"))
        assert "example.com" not in out, "the domain is usually the identifying half"
        assert "dev@" not in out

    def test_one_secret_gets_one_alias_however_it_was_found(self) -> None:
        value = "9f" * 32
        out = scrubbed(f"psk = {value}\nlater the bare {value} again\n")
        assert value not in out
        found = re.findall(r"[0-9a-f]{64}", out)
        assert len(found) == 2
        assert len(set(found)) == 1, "found behind a keyword and bare must share an alias"

    def test_a_labelled_secret_is_scrubbed_where_it_reappears_unlabelled(self) -> None:
        out = scrubbed("password=hunter2fortress\nlogin failed for hunter2fortress\n")
        assert "hunter2fortress" not in out, "the bare second occurrence leaked"

    def test_unparseable_colon_hex_is_reported_rather_than_passed_silently(self) -> None:
        result = scrub("addr aa:bb:cc:dd:ee:ff:11 tail")
        assert result.residuals, "a 7-group colon-hex run must not vanish without a word"
        assert result.residuals[0].text == "aa:bb:cc:dd:ee:ff:11"

    @pytest.mark.parametrize(
        "text",
        ["hw aa:bb:cc:dd:ee:ff-eth0", "iface wlan0-aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff-"],
    )
    def test_a_colon_mac_is_found_next_to_a_hyphen(self, text: str) -> None:
        assert "aa:bb:cc:dd:ee:ff" not in scrub(text).text

    def test_a_hyphen_mac_is_still_fenced_from_a_longer_hyphen_run(self) -> None:
        result = scrub("id AA-BB-CC-DD-EE-FF-11-22")
        assert Kind.MAC not in {f.kind for f in result.findings}

    def test_a_truncated_pem_block_still_loses_its_key(self) -> None:
        # Diagnostics get cut off mid-key routinely; with no END marker the body used to
        # match nothing at all and survive in full.
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
        assert body not in scrubbed(f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n")

    def test_every_eight_group_fingerprint_is_scrubbed(self) -> None:
        # These were routed to IPV6 for alias pooling, where most of the address space
        # reads as reserved and the allowlist kept them verbatim. An ssh-keygen or
        # x509 fingerprint is exactly this shape, so the leak was routine.
        rng = random.Random(0)
        for _ in range(200):
            fp = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(8))
            assert fp not in scrubbed(f"fingerprint {fp} end"), fp

    def test_eight_group_colon_hex_is_scrubbed_even_though_it_parses_as_an_address(
        self,
    ) -> None:
        # ::1 spelled out longhand is indistinguishable from a fingerprint, and guessing
        # wrong in the direction of "keep it" is the expensive mistake.
        assert "00:00:00:00:00:00:00:01" not in scrubbed("x 00:00:00:00:00:00:00:01")

    def test_a_secret_that_is_an_email_shares_the_email_alias_pool(self) -> None:
        out = scrubbed("password=alice@example.com\ncontact alice@example.com\n")
        assert "alice@example.com" not in out
        assert out.count("person-a@example.invalid") == 2

    def test_link_local_identifiers_are_scrubbed_however_they_were_derived(self) -> None:
        # A native EUI-64 carries no ff:fe marker, and an RFC 7217 opaque identifier is
        # stable per network -- both fingerprint the machine.
        for address in ("fe80::0011:2233:4455:6677", "fe80::abcd:1234:5678:9abc"):
            out = scrubbed(f"addr {address}")
            assert address not in out, address
            assert out.strip().startswith("addr fe80::"), "the link-local fact is worth keeping"

    def test_a_hand_assigned_link_local_address_is_kept(self) -> None:
        assert scrubbed("addr fe80::1") == "addr fe80::1"

    def test_timestamps_are_not_reported_as_unrecognized(self) -> None:
        # The whole point of the residual warning is that it gets read; one line per
        # syslog timestamp would train the reader to ignore it.
        result = scrub(JOURNAL, identity=LocalIdentity(hostname="dev-thinkpad", username="dev"))
        assert not [r for r in result.residuals if r.text.startswith("22:20")]


class TestCounts:
    def test_counts_are_reported_per_kind(self) -> None:
        result = scrub(JOURNAL, identity=LocalIdentity(hostname="dev-thinkpad", username="dev"))
        assert result.counts[Kind.MAC] == 2
        assert result.counts[Kind.UUID] == 1


class TestDeterministicAliasing:
    def test_the_same_seed_reproduces_the_output_exactly(self) -> None:
        identity = LocalIdentity(hostname="dev-thinkpad", username="dev")
        first = scrub(JOURNAL, identity, book=AliasBook(random.Random(7)))
        second = scrub(JOURNAL, identity, book=AliasBook(random.Random(7)))
        assert first.text == second.text

    def test_different_seeds_yield_different_aliases(self) -> None:
        first = scrub("hw aa:bb:cc:dd:ee:ff", book=AliasBook(random.Random(0)))
        second = scrub("hw aa:bb:cc:dd:ee:ff", book=AliasBook(random.Random(1)))
        assert first.text != second.text

    def test_a_shared_book_keeps_aliases_consistent_across_documents(self) -> None:
        # Sanitize once and keep the result if you need two pastes to line up — or share
        # one book across both scrubs, which is what makes the pastes correlate.
        book = AliasBook(random.Random(0))
        first = scrub("hw aa:bb:cc:dd:ee:ff up", book=book)
        second = scrub("peer aa:bb:cc:dd:ee:ff replied", book=book)
        alias = re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", first.text)
        assert alias is not None
        assert alias.group() in second.text

    def test_without_a_book_replacements_stay_per_run(self) -> None:
        outputs = {scrub("hw aa:bb:cc:dd:ee:ff").text for _ in range(3)}
        assert len(outputs) == 3, "unseeded runs must not repeat aliases"
