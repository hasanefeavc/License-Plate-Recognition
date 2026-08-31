"""Tests for the offline licensing layer.

The properties that matter are the ones an unlicensed site would attack:
an edited expiry must not verify, a token signed with someone else's key must
not verify, an HS256 token must not be accepted by passing the public key off
as an HMAC secret, and winding the system clock back must not buy any
runtime.
"""

from __future__ import annotations

import importlib.util
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from lpr import license as lic  # noqa: E402


def _keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# One vendor key pair for the whole module (RSA generation is not cheap) plus
# a second, unrelated pair standing in for "somebody else's key".
VENDOR_PRIVATE, VENDOR_PUBLIC = _keypair()
IMPOSTOR_PRIVATE, _IMPOSTOR_PUBLIC = _keypair()


def make_token(
    *,
    days: float = 30.0,
    client: str = "Site A",
    private_key: bytes = VENDOR_PRIVATE,
    issuer: str | None = lic.ISSUER,
    issued_at: datetime | None = None,
) -> str:
    now = issued_at or datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "sub": client,
        "client": client,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=days)).timestamp()),
    }
    if issuer is not None:
        claims["iss"] = issuer
    return jwt.encode(claims, private_key, algorithm=lic.ALGORITHM)


@pytest.fixture()
def public_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install the vendor's public key where the module will find it."""
    path = tmp_path / lic.PUBLIC_KEY_NAME
    path.write_bytes(VENDOR_PUBLIC)
    monkeypatch.setenv(lic.PUBLIC_KEY_ENV_VAR, str(path))
    lic._key_cache.clear()
    return path


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


def test_a_fresh_key_is_valid(public_key: Path) -> None:
    status = lic.validate_token(make_token(days=30))

    assert status.valid is True
    assert status.reason == "ok"
    assert status.client == "Site A"
    assert status.days_remaining == pytest.approx(30.0, abs=0.01)


def test_an_expired_key_is_rejected_but_still_readable(public_key: Path) -> None:
    """The operator on the phone is asked *when* it expired, so say so."""
    issued = datetime.now(timezone.utc) - timedelta(days=40)
    status = lic.validate_token(make_token(days=30, issued_at=issued))

    assert status.valid is False
    assert status.reason == "expired"
    assert status.client == "Site A"
    assert status.expires_at is not None
    assert status.seconds_remaining == 0.0


def test_a_key_signed_with_another_private_key_is_rejected(public_key: Path) -> None:
    status = lic.validate_token(make_token(private_key=IMPOSTOR_PRIVATE))
    assert status.valid is False
    assert status.reason == "invalid"


def test_an_edited_expiry_is_rejected(public_key: Path) -> None:
    """Re-signing is the only way to move ``exp``, and that needs the private key."""
    issued = datetime.now(timezone.utc) - timedelta(days=40)
    header, _payload, signature = make_token(days=30, issued_at=issued).split(".")
    forged_payload = jwt.encode(
        {
            "iss": lic.ISSUER,
            "sub": "Site A",
            "client": "Site A",
            "iat": int(issued.timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp()),
        },
        IMPOSTOR_PRIVATE,
        algorithm=lic.ALGORITHM,
    ).split(".")[1]

    status = lic.validate_token(f"{header}.{forged_payload}.{signature}")

    assert status.valid is False
    assert status.reason == "invalid"


def test_an_hs256_token_signed_with_the_public_key_is_rejected(public_key: Path) -> None:
    """Algorithm confusion: the public key is public, so it is a known "secret".

    If the verifier accepted HS256 as well as RS256, anyone holding
    ``public_key.pem`` -- which is every customer -- could sign their own
    licence with it. Pinning ``algorithms=["RS256"]`` is what stops that.

    The token is assembled by hand rather than through ``jwt.encode``, which
    refuses a PEM as an HMAC secret and would fail here in the *setup* instead
    of at the assertion. That refusal is a second, welcome layer of defence --
    but it lives in the attacker's library, not in ours, so it cannot be what
    this test relies on. A real forger writes the three segments directly.
    """
    forged = _hs256_by_hand(
        {
            "iss": lic.ISSUER,
            "sub": "Forger",
            "client": "Forger",
            "iat": int(time.time()),
            "exp": int(time.time()) + 365 * 86400,
        },
        VENDOR_PUBLIC,
    )
    assert lic.validate_token(forged).valid is False


def _hs256_by_hand(payload: dict[str, object], secret: bytes) -> str:
    """One HS256 JWT, built without asking PyJWT's opinion of the key."""
    import base64
    import hashlib
    import hmac
    import json

    def segment(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    signing_input = b".".join(
        (
            segment(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()),
            segment(json.dumps(payload).encode()),
        )
    )
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return b".".join((signing_input, segment(signature))).decode("ascii")


def test_an_api_session_token_is_not_a_licence(public_key: Path) -> None:
    """Different key, different algorithm, no issuer -- must not be accepted."""
    session = jwt.encode(
        {
            "sub": "admin",
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        "the-api-session-secret",
        algorithm="HS256",
    )
    assert lic.validate_token(session).valid is False


def test_an_empty_key_is_missing_not_invalid(public_key: Path) -> None:
    assert lic.validate_token("   ").reason == "missing"


def test_without_a_public_key_nothing_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(lic.PUBLIC_KEY_ENV_VAR, raising=False)
    monkeypatch.setattr(lic, "public_key_candidates", list)
    lic._key_cache.clear()
    assert lic.validate_token(make_token()).reason == "no_secret"


def test_a_private_key_is_never_accepted_as_the_verifying_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shipping the signing key to a site must fail loudly, not work."""
    wrong = tmp_path / lic.PUBLIC_KEY_NAME
    wrong.write_bytes(VENDOR_PRIVATE)
    monkeypatch.setenv(lic.PUBLIC_KEY_ENV_VAR, str(wrong))
    monkeypatch.setattr(lic, "public_key_candidates", lambda: [wrong])
    lic._key_cache.clear()

    assert lic.load_public_key() is None
    assert lic.validate_token(make_token()).reason == "no_secret"


def test_a_replaced_public_key_is_picked_up_without_a_restart(
    public_key: Path,
) -> None:
    """Re-keying a site is a file copy; the cache must not outlive it."""
    assert lic.validate_token(make_token()).valid is True

    _new_private, new_public = _keypair()
    public_key.write_bytes(new_public)

    assert lic.validate_token(make_token()).valid is False
    assert lic.validate_token(make_token(private_key=_new_private)).valid is True


# ---------------------------------------------------------------------------
# Storage and activation
# ---------------------------------------------------------------------------


def test_activation_persists_the_key(db: Any, public_key: Path) -> None:
    from lpr.db import SystemMetaRepository

    token = make_token(days=10, client="ACME")
    status = lic.activate_license(token)

    assert status.valid is True
    assert SystemMetaRepository().get(lic.LICENSE_TOKEN_KEY) == token
    assert lic.read_license_token() == token
    assert lic.check_license().valid is True


def test_activation_refuses_a_bad_key(db: Any, public_key: Path) -> None:
    from lpr.db import SystemMetaRepository

    with pytest.raises(lic.LicenseError) as excinfo:
        lic.activate_license(make_token(private_key=IMPOSTOR_PRIVATE))

    assert excinfo.value.reason == "invalid"
    assert SystemMetaRepository().get(lic.LICENSE_TOKEN_KEY) is None


def test_activation_writes_a_recovery_file(db: Any, public_key: Path) -> None:
    token = make_token(days=5)
    lic.activate_license(token)

    written = [p for p in lic.license_file_candidates() if p.is_file()]
    assert written, "activation must leave a .license file behind"
    assert written[0].read_text(encoding="utf-8").strip() == token


def test_a_licence_file_survives_a_wiped_database(
    db: Any, public_key: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping a .license next to the service is a supported install path."""
    token = make_token(days=7, client="Dosyadan")
    license_file = tmp_path / lic.LICENSE_FILE_NAME
    license_file.write_text(f"# müşteri: Dosyadan\n{token}\n", encoding="utf-8")
    monkeypatch.setattr(lic, "license_file_candidates", lambda: [license_file])

    assert lic.read_license_token() == token
    assert lic.check_license().client == "Dosyadan"


def test_no_licence_at_all_reads_as_missing(db: Any, public_key: Path, monkeypatch) -> None:
    monkeypatch.setattr(lic, "license_file_candidates", lambda: [])
    assert lic.check_license().reason == "missing"


# ---------------------------------------------------------------------------
# Anti-rollback
# ---------------------------------------------------------------------------


def test_a_rolled_back_clock_invalidates_a_valid_key(db: Any, public_key: Path) -> None:
    """The whole point: an offline expiry date is only as good as the clock."""
    lic.activate_license(make_token(days=30))
    assert lic.check_license().valid is True

    # The site has been seen running a week from now; going back in time
    # must not be worth anything.
    a_week_ahead = time.time() + 7 * 86400
    lic.check_license(now=a_week_ahead)

    status = lic.check_license(now=time.time())
    assert status.valid is False
    assert status.reason == "clock_rollback"


def test_the_clock_high_water_mark_never_goes_backwards(db: Any, public_key: Path) -> None:
    lic.activate_license(make_token(days=30))
    ahead = time.time() + 3600
    lic.check_license(now=ahead)
    lic.check_license(now=ahead - 10)  # inside the tolerance, recorded but lower

    from lpr.db import SystemMetaRepository

    assert float(SystemMetaRepository().get(lic.LAST_RUN_KEY)) == pytest.approx(ahead)


def test_a_small_backwards_correction_is_tolerated(db: Any, public_key: Path) -> None:
    """An NTP correction is not tampering."""
    lic.activate_license(make_token(days=30))
    now = time.time()
    lic.check_license(now=now)

    assert lic.check_license(now=now - 60).valid is True


def test_activation_is_refused_while_the_clock_is_rolled_back(
    db: Any, public_key: Path
) -> None:
    lic.check_license(now=time.time() + 7 * 86400)

    with pytest.raises(lic.LicenseError) as excinfo:
        lic.activate_license(make_token(days=30))
    assert excinfo.value.reason == "clock_rollback"


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


def test_the_guard_caches_and_refreshes(db: Any, public_key: Path) -> None:
    guard = lic.LicenseGuard()
    assert guard.status.valid is False  # nothing installed yet

    guard.activate(make_token(days=3, client="Guard"))
    assert guard.valid is True
    assert guard.status.client == "Guard"

    assert guard.refresh().valid is True
    assert guard.checked_at > 0


# ---------------------------------------------------------------------------
# The generator CLI
# ---------------------------------------------------------------------------


def _load_generator() -> Any:
    """Import ``scripts/generate_license.py``, which is not a package module."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "generate_license.py"
    spec = importlib.util.spec_from_file_location("generate_license", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_generator_mints_a_key_this_module_accepts(public_key: Path) -> None:
    generator = _load_generator()
    token, claims = generator.generate(
        days=30, client="Site A", note="", private_key=VENDOR_PRIVATE
    )

    status = lic.validate_token(token)
    assert status.valid is True
    assert status.client == "Site A"
    assert claims["iss"] == lic.ISSUER


@pytest.fixture()
def private_key_file(tmp_path: Path) -> Path:
    path = tmp_path / "private_key.pem"
    path.write_bytes(VENDOR_PRIVATE)
    return path


def test_the_history_log_never_holds_a_whole_token(
    public_key: Path,
    private_key_file: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The leak this patch closes: the log recorded live, usable licences."""
    generator = _load_generator()
    history = tmp_path / "license_history.log"

    code = generator.main(
        [
            "--days", "30",
            "--client", "Site A",
            "--private-key", str(private_key_file),
            "--history", str(history),
            "--quiet",
        ]
    )
    token = capsys.readouterr().out.strip()
    contents = history.read_text(encoding="utf-8")

    assert code == 0
    assert token not in contents, "the full token must never reach the log"
    # Not even the signature's leading part: only the last 10 characters.
    assert token[:-10] not in contents
    assert f"token_tail=...{token[-10:]}" in contents
    assert lic.validate_token(token).valid is True


def test_the_history_record_still_identifies_the_key(
    public_key: Path, private_key_file: Path, tmp_path: Path
) -> None:
    generator = _load_generator()
    history = tmp_path / "license_history.log"
    args = ["--private-key", str(private_key_file), "--history", str(history), "--quiet"]

    generator.main(["--days", "30", "--client", "Site A", *args])
    generator.main(["--days", "7", "--client", "Site B", *args])

    lines = [
        line
        for line in history.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#")
    ]
    assert len(lines) == 2, "records append, they never replace"
    assert "client=Site A" in lines[0] and "client=Site B" in lines[1]
    for line in lines:
        assert "created=" in line and "expires=" in line and "jti=" in line


def test_the_generator_needs_a_private_key(
    public_key: Path, tmp_path: Path
) -> None:
    generator = _load_generator()
    missing = tmp_path / "nope.pem"
    with pytest.raises(SystemExit):
        generator.main(
            ["--days", "30", "--client", "X", "--private-key", str(missing), "--no-history"]
        )


def test_the_generator_refuses_to_sign_with_the_public_key(
    public_key: Path, tmp_path: Path
) -> None:
    """The obvious mix-up must fail with a reason, not a stack trace."""
    generator = _load_generator()
    with pytest.raises(SystemExit) as excinfo:
        generator.main(
            [
                "--days", "30",
                "--client", "X",
                "--private-key", str(public_key),
                "--no-history",
            ]
        )
    assert "not a PEM private key" in str(excinfo.value)


def test_the_generator_verifies_an_existing_key(
    public_key: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verification needs the public half only, so a site can run it too."""
    generator = _load_generator()
    assert generator.main(["--verify", make_token(days=1)]) == 0
    assert generator.main(["--verify", make_token(private_key=IMPOSTOR_PRIVATE)]) == 2


# ---------------------------------------------------------------------------
# The key-pair generator
# ---------------------------------------------------------------------------


def _load_keygen() -> Any:
    path = Path(__file__).resolve().parents[1] / "scripts" / "generate_keys.py"
    spec = importlib.util.spec_from_file_location("generate_keys", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_keygen_writes_a_usable_pair(tmp_path: Path, monkeypatch) -> None:
    keygen = _load_keygen()
    assert keygen.main(["--out-dir", str(tmp_path / "keys")]) == 0

    private_path = tmp_path / "keys" / "private_key.pem"
    public_path = tmp_path / "keys" / lic.PUBLIC_KEY_NAME
    assert b"PRIVATE KEY" in private_path.read_bytes()
    assert b"BEGIN PUBLIC KEY" in public_path.read_bytes()

    # The pair round-trips through the real sign/verify path.
    generator = _load_generator()
    token, _claims = generator.generate(
        days=1, client="Keygen", note="", private_key=private_path.read_bytes()
    )
    monkeypatch.setenv(lic.PUBLIC_KEY_ENV_VAR, str(public_path))
    lic._key_cache.clear()
    assert lic.validate_token(token).valid is True


def test_the_private_key_is_not_world_readable(tmp_path: Path) -> None:
    import stat as stat_module

    keygen = _load_keygen()
    keygen.main(["--out-dir", str(tmp_path)])
    mode = (tmp_path / "private_key.pem").stat().st_mode
    assert not mode & (stat_module.S_IRGRP | stat_module.S_IROTH)


def test_keygen_refuses_to_clobber_existing_keys(tmp_path: Path) -> None:
    """Regenerating invalidates every licence in the field."""
    keygen = _load_keygen()
    assert keygen.main(["--out-dir", str(tmp_path)]) == 0
    original = (tmp_path / "private_key.pem").read_bytes()

    assert keygen.main(["--out-dir", str(tmp_path)]) == 1
    assert (tmp_path / "private_key.pem").read_bytes() == original

    assert keygen.main(["--out-dir", str(tmp_path), "--force"]) == 0
    assert (tmp_path / "private_key.pem").read_bytes() != original


def test_keygen_refuses_a_weak_key_size(tmp_path: Path) -> None:
    keygen = _load_keygen()
    assert keygen.main(["--out-dir", str(tmp_path), "--key-size", "1024"]) == 1
