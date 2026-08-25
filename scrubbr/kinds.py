from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Kind(StrEnum):
    PEM = "pem"
    CRYPT_HASH = "crypt_hash"
    JWT = "jwt"
    FINGERPRINT = "fingerprint"
    DISK_ID = "disk_id"
    UUID = "uuid"
    MAC = "mac"
    IPV6 = "ipv6"
    LINK_LOCAL_ID = "link_local_id"
    IPV4 = "ipv4"
    HEX = "hex"
    EMAIL = "email"
    SECRET_VALUE = "secret_value"
    REDACTED = "redacted"
    SSID = "ssid"
    HOSTNAME = "hostname"
    USERNAME = "username"
    PERSON = "person"
    PROJECT = "project"
    # Linux-diagnostic identifiers: a stable machine fingerprint (machine-id / boot-id /
    # invocation-id), a hardware serial (dmidecode / disk / WWN / NVMe / IQN), a cloud or
    # kernel-netconfig identifier, and an SSH host-key fingerprint.
    MACHINE_ID = "machine_id"
    HARDWARE_ID = "hardware_id"
    CLOUD_ID = "cloud_id"
    SSH_FINGERPRINT = "ssh_fingerprint"


class Disposition(StrEnum):
    """What a rule does with a match.

    SCRUB rewrites the value; WARN leaves it in place but surfaces it as a review
    warning with a line number; REPORT_ONLY is the low-confidence residual entropy net.
    The gate for SCRUB is distinctiveness -- a fixed prefix plus a validated
    length/charset -- so a collision-prone shape is downgraded to WARN, never suppressed.
    """

    SCRUB = "scrub"
    WARN = "warn"
    REPORT_ONLY = "report_only"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Kind
    start: int
    end: int
    text: str
    alias: str
    disposition: Disposition = Disposition.SCRUB


class Residual(BaseModel):
    model_config = ConfigDict(frozen=True)

    line: int
    text: str
    reason: str
