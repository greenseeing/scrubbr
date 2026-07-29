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


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Kind
    start: int
    end: int
    text: str
    alias: str


class Residual(BaseModel):
    model_config = ConfigDict(frozen=True)

    line: int
    text: str
    reason: str
