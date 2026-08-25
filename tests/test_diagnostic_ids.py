import time

import pytest

from scrubbr import Kind, scrub
from scrubbr.kinds import Disposition

MACHINE_ID = "9a1b2c3d4e5f60718293a4b5c6d7e8f9"  # 32 lowercase hex, no dashes
DASHED_UUID = "550e8400-e29b-41d4-a716-446655440000"
SSH_FP = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"  # 43 base64, no padding

# wpa_supplicant -dd debug dump: the passphrase is in the ascii column, not a key=value.
WPA_PSK_DUMP = (
    "PSK (ASCII passphrase) - hexdump_ascii(len=12):\n"
    "     6d 79 70 61 73 73 77 6f 72 64 31 32   mypassword12\n"
)


class TestMachineAndBootIds:
    def test_a_labelled_machine_id_is_scrubbed_as_machine_id_not_uuid(self) -> None:
        result = scrub(f"_MACHINE_ID={MACHINE_ID}")
        assert MACHINE_ID not in result.text
        kinds = {f.kind for f in result.findings}
        assert Kind.MACHINE_ID in kinds
        assert Kind.UUID not in kinds, "a 32-hex-no-dash id must not be treated as a UUID"

    def test_a_dashed_uuid_is_still_a_uuid_not_a_machine_id(self) -> None:
        result = scrub(f"root=UUID={DASHED_UUID}")
        assert {f.kind for f in result.findings} == {Kind.UUID}

    def test_a_hostnamectl_space_labelled_machine_id_is_typed(self) -> None:
        # `hostnamectl status` prints "Machine ID: <hex>" with a space, not an underscore.
        result = scrub(f"  Machine ID: {MACHINE_ID}")
        assert MACHINE_ID not in result.text
        assert Kind.MACHINE_ID in {f.kind for f in result.findings}

    @pytest.mark.parametrize(
        "line",
        [
            f"_BOOT_ID={MACHINE_ID}",
            f"INVOCATION_ID={MACHINE_ID}",
            f"_SYSTEMD_INVOCATION_ID={MACHINE_ID}",
            f"machine-id: {MACHINE_ID}",
        ],
    )
    def test_boot_and_invocation_ids_are_recognised(self, line: str) -> None:
        assert MACHINE_ID not in scrub(line).text, line


class TestHardwareSerials:
    @pytest.mark.parametrize(
        "line,secret",
        [
            ("Serial Number: PF0ABC123", "PF0ABC123"),
            ("board_serial=CZC1234ABC", "CZC1234ABC"),
            ("nvme id: eui.0025385b71b0125a", "0025385b71b0125a"),
            ("iscsi iqn.1993-08.org.debian:01:a1b2c3d4e5f6", "iqn.1993-08.org.debian:01:a1b2c3d4e5f6"),
            ("disk WWN=0x5000c500a1b2c3d4", "5000c500a1b2c3d4"),
        ],
    )
    def test_a_hardware_identifier_is_scrubbed(self, line: str, secret: str) -> None:
        assert secret not in scrub(line).text, line

    def test_a_dmidecode_placeholder_serial_is_left_alone(self) -> None:
        # "Not Specified"/"None" carry no digit and identify nothing; scrubbing them is noise.
        for placeholder in ("Serial Number: Not Specified", "Serial Number: None"):
            assert scrub(placeholder).text == placeholder, placeholder

    def test_a_udev_id_serial_short_bare_serial_is_caught(self) -> None:
        # `udevadm info` emits the bare serial as ID_SERIAL_SHORT= (a suffix after "serial").
        assert "12345678" not in scrub("E: ID_SERIAL_SHORT=12345678").text


class TestCloudAndKernelIds:
    @pytest.mark.parametrize(
        "line,secret",
        [
            ("instance i-0abc123def4567890 booting", "i-0abc123def4567890"),
            ("account_id=123456789012", "123456789012"),
            ("arn:aws:iam::123456789012:user/alice", "123456789012"),
            ("cloud-config-url=https://metadata.example.com/user-data", "metadata.example.com"),
            (
                "ip=192.168.9.10:192.168.9.1:192.168.9.1:255.255.255.0:myhost01:eth0:off",
                "myhost01",
            ),
        ],
    )
    def test_a_cloud_or_kernel_identifier_is_scrubbed(self, line: str, secret: str) -> None:
        assert secret not in scrub(line).text, line

    def test_two_comma_separated_arns_are_both_scrubbed(self) -> None:
        # A comma-joined ARN list must not collapse into one surrogate, deleting the second.
        out = scrub(
            "roles=arn:aws:iam::111111111111:role/A,arn:aws:iam::222222222222:role/B"
        ).text
        assert "111111111111" not in out and "222222222222" not in out

    def test_a_hand_assigned_link_local_in_an_ip_field_is_kept(self) -> None:
        # The kernel-ip rule must not swallow an ordinary `ip=<ipv6>` connection-log field and
        # override the policy that keeps a hand-assigned link-local (fe80::1) which names nobody.
        text = "src ip=fe80::1 iface=eth0"
        assert scrub(text).text == text


class TestSshFingerprint:
    def test_an_ssh_host_key_fingerprint_is_scrubbed_and_the_prefix_kept(self) -> None:
        out = scrub(f"Accepted publickey for dev: RSA {SSH_FP}").text
        assert "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" not in out
        assert "SHA256:" in out, "the SHA256: prefix stays readable"

    def test_the_fingerprint_finding_is_typed(self) -> None:
        result = scrub(f"RSA {SSH_FP}")
        assert Kind.SSH_FINGERPRINT in {f.kind for f in result.findings}


class TestWifiPskHexdump:
    def test_a_wpa_supplicant_psk_hexdump_line_is_caught(self) -> None:
        out = scrub(WPA_PSK_DUMP).text
        assert "mypassword12" not in out, "the passphrase leaked from the ascii column"
        assert "6d 79 70 61" not in out, "the hex bytes leaked"
        assert "hexdump_ascii(len=12)" in out, "the header stays as evidence a PSK was present"

    def test_the_psk_dump_is_a_scrub_finding(self) -> None:
        result = scrub(WPA_PSK_DUMP)
        assert any(f.disposition is Disposition.SCRUB for f in result.findings)


class TestDiagnosticIdsAreDistinguishableAndIdempotent:
    def test_two_distinct_serials_get_two_distinct_surrogates(self) -> None:
        out = scrub("s1 Serial Number: PF0ABC123 s2 Serial Number: CZC9876XYZ").text
        assert "PF0ABC123" not in out
        assert "CZC9876XYZ" not in out
        assert "serial-a" in out and "serial-b" in out

    def test_re_scrubbing_diagnostic_ids_is_a_fixed_point(self) -> None:
        text = (
            f"_MACHINE_ID={MACHINE_ID}\n"
            f"Serial Number: PF0ABC123\n"
            f"host key RSA {SSH_FP}\n"
            "instance i-0abc123def4567890\n"
        )
        once = scrub(text).text
        assert scrub(once).text == once


class TestDiagnosticRulesDoNotBacktrack:
    def test_a_large_adversarial_input_completes_quickly(self) -> None:
        adversarial = (
            "eui." + "a" * 200_000
            + "SHA256:" + "b" * 200_000
            + "ip=" + "1:" * 100_000
            + "Serial Number: " + "c" * 200_000
        )
        start = time.monotonic()
        scrub(adversarial)
        assert time.monotonic() - start < 5.0

    def test_many_repeated_serial_labels_stay_linear(self) -> None:
        # The quadratic case: MANY label occurrences, each followed by no digit. An unbounded
        # digit lookahead over a ':'-inclusive class made this O(n^2); it must be linear.
        start = time.monotonic()
        scrub("serial:" * 50_000)
        assert time.monotonic() - start < 5.0
