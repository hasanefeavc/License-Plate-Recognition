"""Tests for machine fingerprinting and hardware-bound licences.

The commercial assertion is the last section: a licence issued for machine A
must be refused on machine B. Everything before it is about the property that
makes such a licence usable rather than merely strict -- surviving a component
change that a real machine legitimately undergoes.

No real hardware is read. The component readers are patched, because a test
that asserted anything about *this* machine's MAC would pass or fail depending
on the runner.
"""

from __future__ import annotations

from typing import Any

import pytest

from lpr.machine import (
    COMPONENTS,
    MATCH_THRESHOLD,
    Fingerprint,
    current_fingerprint,
    fingerprint_matches,
    hwid,
)

MACHINE_A = Fingerprint(
    components={"machine_id": "aaaa1111", "mac": "bbbb2222", "board": "cccc3333"}
)
MACHINE_B = Fingerprint(
    components={"machine_id": "dddd4444", "mac": "eeee5555", "board": "ffff6666"}
)


# ---------------------------------------------------------------------------
# Reading components
# ---------------------------------------------------------------------------


def test_components_are_hashed_not_stored_raw(monkeypatch: pytest.MonkeyPatch) -> None:
    """A licence file is e-mailed and lands in a support inbox.

    It must not carry the site's MAC address or serial numbers in the clear,
    so every component is salted and hashed before it leaves the module.
    """
    import lpr.machine as machine

    monkeypatch.setitem(machine._READERS, "mac", lambda: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setitem(machine._READERS, "machine_id", lambda: "deadbeef")
    monkeypatch.setitem(machine._READERS, "board", lambda: "SERIAL-12345")

    fingerprint = current_fingerprint()
    joined = " ".join(fingerprint.components.values())
    assert "aa:bb:cc" not in joined
    assert "deadbeef" not in joined
    assert "SERIAL-12345" not in joined


def test_the_same_input_yields_the_same_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    """A licence is checked on every start-up; an unstable hash would expire it."""
    import lpr.machine as machine

    monkeypatch.setitem(machine._READERS, "mac", lambda: "aa:bb:cc:dd:ee:ff")
    first = current_fingerprint().components["mac"]
    second = current_fingerprint().components["mac"]
    assert first == second


def test_a_component_that_cannot_be_read_is_absent_not_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "We did not look" and "it is blank" decide different things.

    A component the licence names but this host cannot read must not count as
    a mismatch, or an unreadable DMI after a kernel upgrade would close a
    customer's gate.
    """
    import lpr.machine as machine

    monkeypatch.setitem(machine._READERS, "board", lambda: None)
    monkeypatch.setitem(machine._READERS, "mac", lambda: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setitem(machine._READERS, "machine_id", lambda: "deadbeef")

    fingerprint = current_fingerprint()
    assert "board" not in fingerprint.components
    assert fingerprint.available == ("machine_id", "mac")


def test_a_reader_that_raises_does_not_break_fingerprinting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fingerprinting is a refusal mechanism; it must not be able to take the
    service down by failing to read a sysfs file."""
    import lpr.machine as machine

    def explode() -> str:
        raise OSError("permission denied")

    monkeypatch.setitem(machine._READERS, "board", explode)
    monkeypatch.setitem(machine._READERS, "mac", lambda: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setitem(machine._READERS, "machine_id", lambda: "deadbeef")

    fingerprint = current_fingerprint()
    assert fingerprint.bindable
    assert "board" not in fingerprint.components


def test_hwid_is_short_and_stable() -> None:
    assert MACHINE_A.hwid == MACHINE_A.hwid
    assert MACHINE_A.hwid != MACHINE_B.hwid
    assert len(MACHINE_A.hwid) == 16


def test_an_unreadable_machine_has_no_hwid() -> None:
    assert Fingerprint(components={}).hwid == ""


def test_hwid_helper_matches_the_fingerprint() -> None:
    assert hwid() == current_fingerprint().hwid


# ---------------------------------------------------------------------------
# Bindability
# ---------------------------------------------------------------------------


def test_a_machine_with_too_few_components_is_not_bindable() -> None:
    """Issuing a bound licence to it would produce a key that never validates."""
    assert Fingerprint(components={"mac": "bbbb2222"}).bindable is False
    assert Fingerprint(components={}).bindable is False


def test_two_components_are_enough_to_bind() -> None:
    """The common container case: no board serial is exposed."""
    fingerprint = Fingerprint(components={"machine_id": "a", "mac": "b"})
    assert fingerprint.bindable is True
    assert len(fingerprint.components) == MATCH_THRESHOLD


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def test_a_machine_matches_itself() -> None:
    matched, agreeing, mismatched = fingerprint_matches(MACHINE_A.to_claims(), MACHINE_A)
    assert matched and agreeing == 3 and mismatched == []


def test_a_different_machine_does_not_match() -> None:
    matched, agreeing, mismatched = fingerprint_matches(MACHINE_A.to_claims(), MACHINE_B)
    assert not matched
    assert agreeing == 0
    assert sorted(mismatched) == sorted(COMPONENTS)


def test_one_changed_component_out_of_three_is_tolerated() -> None:
    """The property that makes this usable rather than merely strict.

    A replaced network card must not lock a paying customer out of their own
    gate at three in the morning.
    """
    swapped_nic = Fingerprint(components={**MACHINE_A.components, "mac": "9999zzzz"})
    matched, agreeing, mismatched = fingerprint_matches(MACHINE_A.to_claims(), swapped_nic)
    assert matched
    assert agreeing == 2
    assert mismatched == ["mac"]


def test_two_changed_components_are_refused() -> None:
    """Two of three changing is a different machine, not a repair."""
    mostly_new = Fingerprint(
        components={"machine_id": "aaaa1111", "mac": "9999zzzz", "board": "8888yyyy"}
    )
    matched, agreeing, _ = fingerprint_matches(MACHINE_A.to_claims(), mostly_new)
    assert not matched and agreeing == 1


def test_a_component_missing_on_this_host_is_neither_agreement_nor_conflict() -> None:
    """It is not evidence of a copy, so it must not be counted as one."""
    no_board = Fingerprint(components={"machine_id": "aaaa1111", "mac": "bbbb2222"})
    matched, agreeing, mismatched = fingerprint_matches(MACHINE_A.to_claims(), no_board)
    assert matched
    assert agreeing == 2
    assert mismatched == []


def test_a_two_component_host_has_no_slack() -> None:
    """Documented consequence, asserted so it cannot regress silently.

    With only two readable components, losing one leaves a single agreement --
    below the threshold. There is no way around it: tolerating a change with
    two signals means accepting a copied machine-id on a different box.
    """
    two = Fingerprint(components={"machine_id": "aaaa1111", "mac": "bbbb2222"})
    swapped = Fingerprint(components={"machine_id": "aaaa1111", "mac": "9999zzzz"})
    matched, agreeing, _ = fingerprint_matches(two.to_claims(), swapped)
    assert not matched and agreeing == 1


def test_an_unbound_licence_matches_everything() -> None:
    """Not a loophole: the vendor chose to issue it that way."""
    assert fingerprint_matches(None, MACHINE_A)[0] is True
    assert fingerprint_matches({}, MACHINE_B)[0] is True


# ---------------------------------------------------------------------------
# End to end, through a real signed licence
# ---------------------------------------------------------------------------


@pytest.fixture
def public_key(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install the vendor's public key where the validator will find it.

    Reuses the key pair `test_license` already generated for the session --
    RSA generation is not cheap, and a second pair here would double the cost
    of the whole suite for no extra coverage.
    """
    import lpr.license as lic
    from tests.test_license import VENDOR_PUBLIC

    path = tmp_path / lic.PUBLIC_KEY_NAME
    path.write_bytes(VENDOR_PUBLIC)
    monkeypatch.setenv(lic.PUBLIC_KEY_ENV_VAR, str(path))
    lic._key_cache.clear()
    return path


@pytest.fixture
def signed(public_key: Any) -> Any:
    """A helper that mints a licence bound to the given components."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from generate_license import generate

    from tests.test_license import VENDOR_PRIVATE

    def _mint(binding: dict[str, str] | None, client: str = "Site A") -> str:
        token, _claims = generate(
            days=30, client=client, note="", private_key=VENDOR_PRIVATE, binding=binding
        )
        return token

    return _mint


def test_a_licence_for_machine_a_is_refused_on_machine_b(
    signed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The commercial assertion. Without this the licence is a bearer token.

    A file that works on every machine it is copied to means per-site pricing
    rests on nobody noticing.
    """
    import lpr.license as lic
    import lpr.machine as machine

    token = signed(MACHINE_A.to_claims())

    monkeypatch.setattr(machine, "current_fingerprint", lambda: MACHINE_A)
    assert lic.validate_token(token).valid is True

    monkeypatch.setattr(machine, "current_fingerprint", lambda: MACHINE_B)
    status = lic.validate_token(token)
    assert status.valid is False
    assert status.reason == lic.REASON_MACHINE_MISMATCH


def test_a_mismatch_reports_the_hwid_so_a_rebind_can_be_requested(
    signed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one refusal with a remedy the customer can act on.

    The moment somebody needs their machine id is the moment the gate is down,
    so it is on the status rather than behind a separate tool.
    """
    import lpr.license as lic
    import lpr.machine as machine

    monkeypatch.setattr(machine, "current_fingerprint", lambda: MACHINE_B)
    status = lic.validate_token(signed(MACHINE_A.to_claims()))

    assert status.hwid == MACHINE_B.hwid
    assert sorted(status.machine_mismatch) == sorted(COMPONENTS)
    assert "hwid" in status.detail


def test_a_mismatch_is_not_reported_as_a_forgery(
    signed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`invalid` sends the operator looking for a typo in a well-formed key."""
    import lpr.license as lic
    import lpr.machine as machine

    monkeypatch.setattr(machine, "current_fingerprint", lambda: MACHINE_B)
    assert lic.validate_token(signed(MACHINE_A.to_claims())).reason != lic.REASON_INVALID


def test_an_unbound_licence_still_works_anywhere(
    signed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Evaluation keys keep working; binding is opt-in at issue time."""
    import lpr.license as lic
    import lpr.machine as machine

    token = signed(None, client="Evaluation")
    for fingerprint in (MACHINE_A, MACHINE_B):
        monkeypatch.setattr(machine, "current_fingerprint", lambda f=fingerprint: f)
        assert lic.validate_token(token).valid is True


def test_a_bound_licence_is_accepted_when_the_fingerprint_cannot_be_read(
    signed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable fingerprint is not evidence of a copy.

    The alternative is that an unreadable sysfs after a kernel upgrade closes
    a customer's gate, which is a worse outcome than the copying this prevents.
    """
    import lpr.license as lic

    monkeypatch.setattr(lic, "_machine_fingerprint", lambda: None)
    assert lic.validate_token(signed(MACHINE_A.to_claims())).valid is True


def test_an_expired_bound_licence_reports_expiry_not_the_machine(
    public_key: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The binding is checked last, and only on a token that is otherwise good.

    An operator must not be sent chasing a hardware problem when the real
    fault is an expired licence.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from generate_license import generate

    import lpr.license as lic
    import lpr.machine as machine
    from tests.test_license import VENDOR_PRIVATE

    token, _ = generate(
        days=-1,
        client="Site A",
        note="",
        private_key=VENDOR_PRIVATE,
        binding=MACHINE_A.to_claims(),
    )
    monkeypatch.setattr(machine, "current_fingerprint", lambda: MACHINE_B)
    assert lic.validate_token(token).reason == lic.REASON_EXPIRED
