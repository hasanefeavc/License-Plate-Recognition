"""Machine fingerprinting for hardware-bound licences.

A licence that names only a customer is a bearer token: the file works on every
machine it is copied to, and per-site pricing rests on nobody noticing. Binding
it to the hardware is what makes a site licence a site licence.

The hard part is not producing an identifier. It is producing one that survives
the things that legitimately happen to a running machine -- a NIC replaced, a
container rebuilt, a disk swapped after a failure -- while still refusing a
straight copy to a different box. An identifier that is too strict locks a
paying customer out of their own gate at three in the morning, which is a worse
commercial outcome than the copying it was meant to prevent.

So: three independent components, and a licence matches when **any two** agree.

``machine-id``
    ``/etc/machine-id`` on Linux, the ``MachineGuid`` registry value on
    Windows, ``IOPlatformUUID`` on macOS. The most stable of the three -- it
    survives hardware changes entirely -- and the easiest to copy, because it
    is a file. Strong on its own only in combination.

``mac``
    The primary network interface's hardware address. Survives an OS
    reinstall; changes when the NIC does. Deliberately *not* "all MACs", which
    would change every time a container, a VPN or a USB tether appeared.

``board``
    CPU / baseboard / product serial, read from DMI. The component that most
    genuinely identifies the physical machine, and the one most often
    unreadable: it needs privileges on many hosts and is absent in most
    containers.

Each component is hashed with a fixed salt before it leaves this module, so a
licence file -- which a customer may e-mail, and which lands in a support
inbox -- never carries the site's MAC address or serial numbers in the clear.

Nothing here raises. A component that cannot be read is simply absent, and the
two-of-three rule is what keeps the result usable on a host where only one can
be.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = [
    "COMPONENTS",
    "MATCH_THRESHOLD",
    "Fingerprint",
    "current_fingerprint",
    "fingerprint_matches",
    "hwid",
]

#: Component names, in the order they are reported. Stable: they are claim
#: keys inside a signed licence, so renaming one invalidates every key issued.
COMPONENTS: tuple[str, ...] = ("machine_id", "mac", "board")

#: How many components must agree for a licence to be considered bound to this
#: machine.
#:
#: Two, not three. Requiring all three means a replaced network card locks a
#: paying customer out of their own gate, and the component most likely to be
#: missing (``board``) is missing on exactly the containerised hosts this
#: product ships on. Requiring one would accept a copied ``/etc/machine-id``
#: on a different box, which is the case the binding exists to refuse.
MATCH_THRESHOLD = 2

#: Domain separation for the hashes. Not a secret -- it is in the source of
#: every install -- and not pretending to be: its job is to stop a hash here
#: colliding with the same value hashed for some other purpose, and to make a
#: leaked fingerprint useless as a lookup key against a rainbow table of MACs.
_SALT = b"lpr-machine-fingerprint-v1"

#: Length of a component digest, in hex characters. 16 is 64 bits, which is
#: far beyond what is needed to tell a few thousand sites apart and short
#: enough to keep a licence token small and a support ticket readable.
_DIGEST_CHARS = 16

#: DMI files holding a board or product serial, most specific first.
_DMI_PATHS = (
    "/sys/class/dmi/id/product_uuid",
    "/sys/class/dmi/id/board_serial",
    "/sys/class/dmi/id/product_serial",
)

#: Values DMI reports when the field exists but says nothing. Treating these
#: as a serial would give every machine from one vendor the same fingerprint.
_DMI_PLACEHOLDERS = frozenset(
    {
        "",
        "none",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "default string",
        "not specified",
        "not applicable",
        "system serial number",
        "0",
        "00000000",
        "unknown",
        "x.x.x",
        "invalid",
    }
)

#: Locally-administered / virtual MAC prefixes to skip when picking the
#: primary interface. Docker's bridge and most VM hypervisors hand out
#: addresses that change with the container, which is the opposite of what a
#: fingerprint needs.
_VIRTUAL_MAC_PREFIXES = ("02:42:", "0a:00:27:", "00:05:69:", "00:1c:14:", "00:50:56:")

#: Interface names never used as the primary NIC.
_SKIP_INTERFACES = ("lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "cni")


def _digest(value: str) -> str:
    """Salted truncated SHA-256 of one component value."""
    return hashlib.sha256(_SALT + value.strip().lower().encode("utf-8")).hexdigest()[:_DIGEST_CHARS]


# ---------------------------------------------------------------------------
# Component readers. Each returns a raw value or None; never raises.
# ---------------------------------------------------------------------------


def _read_machine_id() -> str | None:
    """The OS installation identifier."""
    if sys.platform.startswith("linux"):
        # /etc/machine-id is empty on some images until first boot completes;
        # systemd writes the same value to /var/lib/dbus/machine-id.
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                value = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                continue
            if value:
                return value
        return None

    if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value).strip() or None
        except Exception:
            return None

    if sys.platform == "darwin":  # pragma: no cover - exercised on macOS only
        output = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        if output:
            match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', output)
            if match:
                return match.group(1)
        return None

    return None


def _read_mac() -> str | None:
    """The primary interface's hardware address.

    "Primary" means the first physical-looking interface in sorted order --
    not every MAC on the box. A fingerprint built from all of them changes
    whenever a container starts, a VPN connects or somebody tethers a phone,
    which would make the licence fail for reasons that have nothing to do with
    the hardware.
    """
    sysfs = Path("/sys/class/net")
    if sysfs.is_dir():
        for interface in sorted(sysfs.iterdir(), key=lambda p: p.name):
            name = interface.name
            if any(name.startswith(prefix) for prefix in _SKIP_INTERFACES):
                continue
            try:
                address = (interface / "address").read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if not address or address == "00:00:00:00:00:00":
                continue
            if any(address.startswith(prefix) for prefix in _VIRTUAL_MAC_PREFIXES):
                continue
            return address.lower()

    # Fallback for non-Linux. uuid.getnode() invents a random address when it
    # cannot find a real one and flags that in the 8th bit of the first octet;
    # a random value would produce a different fingerprint every run, so it is
    # rejected rather than used.
    try:
        node = uuid.getnode()
    except Exception:  # pragma: no cover - platform without a node id
        return None
    if (node >> 40) & 0x01:
        return None
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def _run(command: list[str], timeout: float = 3.0) -> str | None:
    """One short read-only command, or None. Never raises, never uses a shell."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _read_board() -> str | None:
    """A board / product serial from DMI, when the host will part with one."""
    if sys.platform.startswith("linux"):
        for path in _DMI_PATHS:
            try:
                value = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                # Unreadable is the normal case: these need root, and most of
                # them do not exist in a container at all.
                continue
            if value.lower() not in _DMI_PLACEHOLDERS:
                return value
        return None

    if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
        output = _run(["wmic", "csproduct", "get", "UUID"]) or _run(
            ["wmic", "baseboard", "get", "SerialNumber"]
        )
        if not output:
            return None
        for line in output.splitlines()[1:]:
            value = line.strip()
            if value and value.lower() not in _DMI_PLACEHOLDERS:
                return value
        return None

    if sys.platform == "darwin":  # pragma: no cover - exercised on macOS only
        output = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        if output:
            match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', output)
            if match:
                return match.group(1)
        return None

    return None


_READERS = {
    "machine_id": _read_machine_id,
    "mac": _read_mac,
    "board": _read_board,
}


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """Hashed identifiers for one machine.

    ``components`` maps a name from :data:`COMPONENTS` to its digest. A
    component that could not be read is absent rather than empty, so "we did
    not look" and "it is blank" are never confused -- the difference decides
    whether a mismatch is a different machine or an unreadable one.
    """

    components: dict[str, str] = field(default_factory=dict)

    @property
    def hwid(self) -> str:
        """A short, stable, human-quotable id for this machine.

        Derived from every component that *could* be read, so it changes when
        one becomes readable. Fine for a support ticket or a licence request,
        and never used for matching -- :func:`fingerprint_matches` compares
        components so it can tolerate one of them changing.
        """
        if not self.components:
            return ""
        joined = "|".join(f"{name}={self.components[name]}" for name in sorted(self.components))
        return hashlib.sha256(_SALT + joined.encode("utf-8")).hexdigest()[:_DIGEST_CHARS]

    @property
    def available(self) -> tuple[str, ...]:
        return tuple(name for name in COMPONENTS if name in self.components)

    @property
    def bindable(self) -> bool:
        """Whether this machine can be bound at all.

        Needs at least :data:`MATCH_THRESHOLD` components: a machine that can
        only ever present one could never satisfy the two-of-three rule, so
        issuing a bound licence for it would produce a key that never
        validates.
        """
        return len(self.components) >= MATCH_THRESHOLD

    def to_claims(self) -> dict[str, str]:
        """The subset of a licence's claims that carries the binding."""
        return dict(self.components)

    def describe(self) -> str:
        present = ", ".join(self.available) or "none"
        return f"hwid={self.hwid or '(unbindable)'} components={present}"


def current_fingerprint() -> Fingerprint:
    """Read this machine's components. Never raises; absent is not an error.

    Deliberately uncached. It is read at start-up and on a licence check --
    a handful of times an hour -- and caching would hide exactly the change
    this is meant to notice: a container that came up before its network did
    would otherwise hold a fingerprint with no MAC in it for the life of the
    process.
    """
    components: dict[str, str] = {}
    for name in COMPONENTS:
        try:
            raw = _READERS[name]()
        except Exception:  # pragma: no cover - readers are already total
            logger.debug("Fingerprint component %s failed", name, exc_info=True)
            continue
        if raw:
            components[name] = _digest(str(raw))
    return Fingerprint(components=components)


def hwid() -> str:
    """Shorthand for ``current_fingerprint().hwid``, for the CLI and the UI."""
    return current_fingerprint().hwid


def fingerprint_matches(
    claimed: dict[str, str] | None,
    actual: Fingerprint | None = None,
    *,
    threshold: int = MATCH_THRESHOLD,
) -> tuple[bool, int, list[str]]:
    """Does ``claimed`` describe the machine we are running on?

    Returns ``(matched, agreeing, mismatched_names)``.

    ``claimed`` is the binding carried in a licence: ``None`` or empty means
    the licence is unbound, which matches everything. That is not a loophole
    -- an unbound licence is one the vendor chose to issue that way, and the
    decision belongs at issue time.

    Comparison is only ever over components *both* sides have. A component the
    licence names but this host cannot read is neither agreement nor
    disagreement: counting it as a mismatch would reject a valid licence
    whenever DMI became unreadable after a kernel upgrade.
    """
    if not claimed:
        return True, 0, []

    fingerprint = actual if actual is not None else current_fingerprint()
    agreeing = 0
    mismatched: list[str] = []
    for name in COMPONENTS:
        expected = claimed.get(name)
        present = fingerprint.components.get(name)
        if not expected or not present:
            continue
        if expected == present:
            agreeing += 1
        else:
            mismatched.append(name)

    return agreeing >= max(1, int(threshold)), agreeing, mismatched


def describe_environment() -> str:
    """One line for a support ticket: platform, hwid and what was readable."""
    fingerprint = current_fingerprint()
    return (
        f"{platform.system()} {platform.release()} "
        f"({'container' if _in_container() else 'host'}) {fingerprint.describe()}"
    )


def _in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except OSError:
        return False
    return "docker" in content or "kubepods" in content or "podman" in content
