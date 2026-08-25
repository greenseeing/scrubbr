import getpass
import socket
from dataclasses import dataclass, field
from pathlib import Path

from scrubbr.kinds import Kind

SYSTEM_USERNAMES = frozenset(
    {
        "root",
        "daemon",
        "bin",
        "sys",
        "sync",
        "man",
        "nobody",
        "messagebus",
        "dbus",
        "polkitd",
        "sshd",
        "www-data",
        "systemd-network",
        "systemd-resolve",
        "systemd-timesync",
        "systemd-journal",
        "user",
    }
)


@dataclass(frozen=True)
class LocalIdentity:
    """Literal strings naming *this* machine and *this* person.

    Seeding the scanner with these is the highest-precision rule available: the surest
    way to know a hostname is yours is to ask the system for it, rather than to guess at
    which token in a syslog line is a hostname.
    """

    hostname: str | None = None
    username: str | None = None
    extra: tuple[str, ...] = field(default_factory=tuple)
    # Declared values whose surrogate kind the caller has named (--also-host / -person /
    # -project): forced past the keep-allowlists like `extra`, but typed rather than
    # shape-classified so the surrogate reads as host-a / person-b / project-c.
    roles: tuple[tuple[str, Kind], ...] = field(default_factory=tuple)

    @classmethod
    def local(cls) -> "LocalIdentity":
        extra: list[str] = []
        try:
            machine_id = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
        except OSError:
            machine_id = ""
        if machine_id:
            extra.append(machine_id)
        try:
            username: str | None = getpass.getuser()
        except (OSError, KeyError):
            username = None
        try:
            hostname: str | None = socket.gethostname()
        except OSError:
            hostname = None
        return cls(hostname=hostname, username=username, extra=tuple(extra))
