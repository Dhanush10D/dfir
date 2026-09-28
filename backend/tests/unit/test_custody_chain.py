"""Pure hash-chain + signature verification (guide 8.3, 22.2 property tests)."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from app.core.signing import CustodySigner
from app.services.custody import (
    GENESIS,
    ChainEntry,
    build_entry,
    canonical,
    check_detail,
    compute_entry_hash,
    entry_body,
    format_ts,
    verify_chain,
)

SIGNER = CustodySigner("k1", Ed25519PrivateKey.generate())
KEYS = {"k1": SIGNER.public_key}
EVIDENCE = str(uuid.UUID(int=7))
T0 = datetime(2026, 9, 14, 9, 0, 0, 123456, tzinfo=UTC)
ACTIONS = ["created", "ingested", "hash_verified", "locked", "downloaded", "hash_verified"]


def make_chain(n: int = 6, signer: CustodySigner = SIGNER) -> list[ChainEntry]:
    entries: list[ChainEntry] = []
    prev = GENESIS
    for i in range(n):
        entry = build_entry(
            signer,
            evidence_id=EVIDENCE,
            seq=i + 1,
            ts=T0 + timedelta(seconds=i),
            actor_id=uuid.UUID(int=1),
            actor_label="Ann Analyst <ann@example.org>",
            action=ACTIONS[i % len(ACTIONS)],
            detail={"n": i, "sha256": "a" * 64, "nested": {"k": [1, "two", None, True]}},
            prev_hash=prev,
        )
        entries.append(entry)
        prev = entry.entry_hash
    return entries


def problems(entries: list[ChainEntry]) -> set[tuple[int, str]]:
    report = verify_chain(entries, KEYS, evidence_id=EVIDENCE)
    return {(p.seq, p.code) for p in report.problems}


def test_valid_chain() -> None:
    chain = make_chain()
    report = verify_chain(chain, KEYS, evidence_id=EVIDENCE)
    assert report.ok and report.entries == 6
    assert report.head_seq == 6 and report.head_hash == chain[-1].entry_hash
    assert report.first_broken_seq is None
    assert chain[0].prev_hash == GENESIS
    assert report.as_dict()["ok"] is True


def test_canonical_form_and_hash_are_stable() -> None:
    body = entry_body(
        evidence_id=EVIDENCE,
        seq=1,
        ts=T0,
        actor_id=None,
        actor_label="Système",
        action="created",
        detail={"b": 1, "a": "ü"},
        prev_hash=GENESIS,
    )
    assert body["ts"] == "2026-09-14T09:00:00.123456Z"
    assert canonical({"b": 1, "a": "ü"}) == '{"a":"ü","b":1}'.encode()
    assert compute_entry_hash(body) == compute_entry_hash(dict(reversed(list(body.items()))))
    assert format_ts(T0.astimezone(timezone_plus(5))) == "2026-09-14T09:00:00.123456Z"
    with pytest.raises(ValueError):
        format_ts(datetime(2026, 1, 1))


def timezone_plus(hours: int) -> Any:
    from datetime import timezone

    return timezone(timedelta(hours=hours))


def test_edited_detail_reported_at_exact_seq() -> None:
    chain = make_chain()
    chain[2] = dataclasses.replace(chain[2], detail={"n": 999})
    assert problems(chain) == {(3, "hash_mismatch")}


@pytest.mark.parametrize(
    "change",
    [
        {"ts": T0 - timedelta(days=1)},
        {"actor_label": "Mallory"},
        {"actor_id": str(uuid.UUID(int=2))},
        {"action": "note"},
        {"evidence_id": str(uuid.UUID(int=8))},
    ],
)
def test_any_recorded_field_edit_is_detected(change: dict[str, Any]) -> None:
    chain = make_chain()
    chain[3] = dataclasses.replace(chain[3], **change)
    found = problems(chain)
    assert (4, "hash_mismatch") in found
    assert {seq for seq, _ in found} == {4}


def test_rehashed_edit_breaks_signature_and_next_link() -> None:
    chain = make_chain()
    attacker = CustodySigner("k1", Ed25519PrivateKey.generate())
    forged = build_entry(
        attacker,
        evidence_id=EVIDENCE,
        seq=2,
        ts=chain[1].ts,
        actor_id=chain[1].actor_id,
        actor_label=chain[1].actor_label,
        action=chain[1].action,
        detail={"forged": True},
        prev_hash=chain[1].prev_hash,
    )
    chain[1] = forged
    assert problems(chain) == {(2, "bad_signature"), (3, "broken_link")}


def test_deleted_entry() -> None:
    chain = make_chain()
    del chain[2]
    assert problems(chain) == {(4, "seq_gap"), (4, "broken_link")}


def test_deleted_first_entry() -> None:
    chain = make_chain()
    del chain[0]
    assert problems(chain) == {(2, "seq_gap"), (2, "broken_link")}


def test_reordered_entries() -> None:
    chain = make_chain()
    a, b = chain[1], chain[2]
    chain[1] = dataclasses.replace(b, seq=2)
    chain[2] = dataclasses.replace(a, seq=3)
    found = problems(chain)
    assert {seq for seq, _ in found} == {2, 3, 4}
    assert (2, "broken_link") in found and (2, "hash_mismatch") in found


def test_swapped_positions_without_renumbering_are_sorted_by_seq() -> None:
    chain = make_chain()
    chain.reverse()  # storage order must not matter
    assert problems(chain) == set()


def test_duplicate_seq() -> None:
    chain = make_chain(3)
    chain.append(chain[1])
    assert (2, "duplicate_seq") in problems(chain)


def test_forged_entry_with_foreign_key_and_untrusted_key() -> None:
    chain = make_chain(3)
    rogue = CustodySigner("rogue", Ed25519PrivateKey.generate())
    fake = build_entry(
        rogue,
        evidence_id=EVIDENCE,
        seq=4,
        ts=T0 + timedelta(minutes=5),
        actor_id=None,
        actor_label="x",
        action="transferred",
        detail={},
        prev_hash=chain[-1].entry_hash,
    )
    assert problems([*chain, fake]) == {(4, "untrusted_key")}
    impostor = dataclasses.replace(fake, key_id="k1")
    assert problems([*chain, impostor]) == {(4, "bad_signature")}


@pytest.mark.parametrize("signature", ["", "zz", "00" * 64, "not-hex-at-all"])
def test_garbage_signatures(signature: str) -> None:
    chain = make_chain(2)
    chain[0] = dataclasses.replace(chain[0], signature=signature)
    assert problems(chain) == {(1, "bad_signature")}


def test_empty_chain() -> None:
    assert problems([]) == {(0, "empty_chain")}
    assert verify_chain([], KEYS, require_entries=False).ok


def test_entry_from_other_evidence() -> None:
    chain = make_chain(2)
    report = verify_chain(chain, KEYS, evidence_id=str(uuid.UUID(int=9)))
    assert {p.code for p in report.problems} == {"evidence_mismatch"}


def test_detail_must_round_trip_through_jsonb() -> None:
    check_detail({"a": [1, "x", None, True, {"b": -5}]})
    for bad in ({"f": 1.5}, {"s": "nul\x00"}, {1: "int key"}, {"o": object()}):
        with pytest.raises(ValueError):
            check_detail(bad)


FIELDS = ["seq", "ts", "actor_id", "actor_label", "action", "detail", "prev_hash", "entry_hash"]


@settings(max_examples=150, deadline=None)
@given(
    index=st.integers(min_value=0, max_value=5),
    field=st.sampled_from(FIELDS),
    salt=st.text(min_size=1, max_size=8),
    delta=st.integers(min_value=1, max_value=10_000),
)
def test_property_any_single_mutation_is_detected(
    index: int, field: str, salt: str, delta: int
) -> None:
    chain = make_chain()
    entry = chain[index]
    value: Any
    if field == "seq":
        value = entry.seq + delta
    elif field == "ts":
        value = entry.ts + timedelta(microseconds=delta)
    elif field == "detail":
        value = {**entry.detail, "x": salt}
    elif field in {"prev_hash", "entry_hash"}:
        original = getattr(entry, field)
        value = format(int(original, 16) ^ delta, "064x")
    else:
        value = f"{getattr(entry, field)}{salt}"
    chain[index] = dataclasses.replace(entry, **{field: value})
    report = verify_chain(chain, KEYS, evidence_id=EVIDENCE)
    assert not report.ok
    assert report.first_broken_seq is not None


def test_published_key_is_not_a_trust_anchor() -> None:
    """A key an attacker publishes (e.g. in signing_keys) never makes its signatures valid."""
    attacker = CustodySigner("evil", Ed25519PrivateKey.generate())
    chain = make_chain(3, signer=attacker)
    report = verify_chain(chain, KEYS, published_keys={"evil": attacker.public_key})
    assert {(p.seq, p.code) for p in report.problems} == {(i, "untrusted_key") for i in (1, 2, 3)}


def test_published_key_differing_from_trusted_key_is_flagged() -> None:
    chain = make_chain(2)
    impostor = Ed25519PrivateKey.generate().public_key()
    report = verify_chain(chain, KEYS, published_keys={"k1": impostor})
    assert {(p.seq, p.code) for p in report.problems} == {
        (1, "untrusted_key"),
        (2, "untrusted_key"),
    }
    same = verify_chain(chain, KEYS, published_keys={"k1": SIGNER.public_key})
    assert same.ok


def test_chain_signed_by_attacker_under_real_key_id() -> None:
    attacker = CustodySigner("k1", Ed25519PrivateKey.generate())
    chain = make_chain(3, signer=attacker)
    report = verify_chain(chain, KEYS, published_keys={"k1": attacker.public_key})
    codes = {(p.seq, p.code) for p in report.problems}
    assert {(1, "bad_signature"), (1, "untrusted_key")} <= codes
    assert report.broken_seqs == [1, 2, 3]
