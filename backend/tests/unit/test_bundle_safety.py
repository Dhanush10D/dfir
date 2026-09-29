"""Phase 5: triage bundles are hostile input (app.collection.*). No Docker, no network."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import posixpath
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.collection.bundle import BundleLimits, BundleReader, BundleRejectedError
from app.collection.manifest import ManifestError, parse_manifest
from app.collection.names import unsafe_name_reason
from app.collection.trust import PACKAGED, collector_trust, load_trusted_collectors

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BUNDLES = FIXTURES / "bundles"
REPO = Path(__file__).resolve().parents[3]
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()


def _open(path: Path, tmp_path: Path, **limits: int) -> tuple[list[str], dict[str, int], Path]:
    dest = tmp_path / "members"
    with BundleReader(path, BundleLimits(**limits)) as reader:
        manifest, _ = reader.read_manifest()
        result = reader.extract(dest, manifest)
    return [m.status for m in result.members], result.counts(), dest


def _rejected(path: Path, tmp_path: Path, **limits: int) -> BundleRejectedError:
    with pytest.raises(BundleRejectedError) as info:
        _open(path, tmp_path, **limits)
    assert not (tmp_path / "members").exists() or not any((tmp_path / "members").iterdir())
    return info.value


def _manifest(files: list[dict[str, object]], **extra: object) -> bytes:
    body: dict[str, object] = {
        "schema": "dfirbench.triage/1",
        "collector": {"name": "c", "version": "1"},
        "started_at": "2026-01-03T00:00:00Z",
        "files": files,
    }
    body.update(extra)
    return json.dumps(body).encode()


def _zip(path: Path, members: list[tuple[str, bytes]], method: int = zipfile.ZIP_DEFLATED) -> Path:
    with zipfile.ZipFile(path, "w", compression=method) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return path


# ---------------------------------------------------------------------------------- names


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("logs/auth.log", None),
        ("logs/Microsoft-Windows-PowerShell%4Operational.evtx", None),
        ("files/home/alice/.bash_history", None),
        ("files/users/Jos\u00e9/NTUSER.DAT", None),
        ("../evil", "dot_component"),
        ("logs/../../evil", "dot_component"),
        ("logs/./x", "dot_component"),
        ("/etc/passwd", "absolute_path"),
        ("C:/Windows/evil.dll", "drive_letter"),
        ("c:evil", "drive_letter"),
        ("logs\\..\\evil", "backslash"),
        ("logs//x", "empty_component"),
        ("logs/x\x00.txt", "control_character"),
        ("logs/x\n", "control_character"),
        ("", "empty_name"),
        ("a/" * 40 + "x", "too_deep"),
        ("x" * 600, "name_too_long"),
        ("logs/" + "y" * 300, "component_too_long"),
        ("logs/\udcff", "invalid_unicode"),
    ],
)
def test_member_name_rules(name: str, reason: str | None) -> None:
    assert unsafe_name_reason(name) == reason


def test_directory_names_may_end_with_slash() -> None:
    assert unsafe_name_reason("logs/", directory=True) is None
    assert unsafe_name_reason("logs/") == "empty_component"


@settings(max_examples=400, deadline=None)
@given(st.text(max_size=80))
def test_accepted_names_never_escape(name: str) -> None:
    reason = unsafe_name_reason(name)  # never raises
    if reason is None:
        normalized = posixpath.normpath(name)
        assert not normalized.startswith(("/", "..")) and "\\" not in name
        assert posixpath.join("/scratch", normalized).startswith("/scratch/")


# ---------------------------------------------------------------------------------- fixtures


def test_good_bundle_extracts_only_fixed_names(tmp_path: Path) -> None:
    _, counts, dest = _open(BUNDLES / "good.zip", tmp_path)
    assert counts == {"verified": 3}
    names = sorted(p.name for p in dest.iterdir())
    assert names == ["00000.bin", "00001.bin", "00002.bin"]
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == sorted(dest.iterdir())
    assert (dest / "00000.bin").read_bytes() == AUTH_LOG
    for path in dest.iterdir():
        assert not os.access(path, os.W_OK)  # read-only copies for the parsers


def test_mismatches_are_quarantined_not_accepted(tmp_path: Path) -> None:
    dest = tmp_path / "members"
    with BundleReader(BUNDLES / "mismatch.zip", BundleLimits()) as reader:
        manifest, digest = reader.read_manifest()
        result = reader.extract(dest, manifest)
    by_path = {m.path: m for m in result.members}
    assert by_path["logs/var/log/auth.log"].status == "verified"
    assert by_path["logs/var/log/auth.log"].file is not None
    evtx = by_path["logs/Security.evtx"]
    assert evtx.status == "hash_mismatch" and evtx.file is None
    assert evtx.sha256_manifest == "f" * 64 and evtx.sha256_actual != evtx.sha256_manifest
    assert by_path["files/unlisted.txt"].status == "unlisted"
    assert by_path["logs/var/log/missing.log"].status == "missing"
    assert len(result.flagged) == 3
    assert (
        digest
        == hashlib.sha256(
            zipfile.ZipFile(BUNDLES / "mismatch.zip").read("manifest.json")
        ).hexdigest()
    )


@pytest.mark.parametrize(
    ("fixture", "code", "reason"),
    [
        ("traversal_dotdot.zip", "unsafe_name", "dot_component"),
        ("traversal_nested.zip", "unsafe_name", "dot_component"),
        ("traversal_absolute.zip", "unsafe_name", "absolute_path"),
        ("traversal_drive.zip", "unsafe_name", "drive_letter"),
        ("traversal_backslash.zip", "unsafe_name", "backslash"),
        ("symlink.zip", "symlink", None),
        ("bomb_ratio.zip", "compression_ratio", None),
        ("duplicate.zip", "duplicate_name", None),
        ("duplicate_case.zip", "duplicate_name_casefold", None),
        ("encrypted.zip", "encrypted_member", None),
        ("overlap.zip", "overlapping_entries", None),
        ("no_manifest.zip", "manifest_missing", None),
        ("bad_manifest.zip", "manifest_invalid", None),
    ],
)
def test_malicious_bundles_are_rejected(
    fixture: str, code: str, reason: str | None, tmp_path: Path
) -> None:
    exc = _rejected(BUNDLES / fixture, tmp_path)
    assert code in exc.codes
    if reason is not None:
        assert any(r.get("reason") == reason for r in exc.reasons)


def test_member_count_limit(tmp_path: Path) -> None:
    assert (
        "too_many_members" in _rejected(BUNDLES / "bomb_count.zip", tmp_path, max_members=50).codes
    )
    _, counts, _ = _open(BUNDLES / "bomb_count.zip", tmp_path)  # fine under the default limit
    assert counts == {"verified": 60}


def test_total_and_member_size_limits(tmp_path: Path) -> None:
    exc = _rejected(BUNDLES / "good.zip", tmp_path, max_total_bytes=10_000)
    assert "total_too_large" in exc.codes
    exc = _rejected(BUNDLES / "good.zip", tmp_path / "b", max_member_bytes=1000)
    assert "member_too_large" in exc.codes


def test_non_zip_archives_are_refused(tmp_path: Path) -> None:
    gz = tmp_path / "b.tar.gz"
    gz.write_bytes(gzip.compress(b"x" * 100))
    assert _rejected(gz, tmp_path).codes == ["unsupported_archive"]
    tar_path = tmp_path / "b.tar"
    with tarfile.open(tar_path, "w") as tf:
        data = io.BytesIO(b"hello")
        ti = tarfile.TarInfo("logs/x")
        ti.size = 5
        tf.addfile(ti, data)
        link = tarfile.TarInfo("logs/hard")
        link.type = tarfile.LNKTYPE
        link.linkname = "/etc/shadow"
        tf.addfile(link)
    assert _rejected(tar_path, tmp_path).codes == ["unsupported_archive"]
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    assert _rejected(junk, tmp_path).codes == ["not_a_zip"]
    truncated = tmp_path / "trunc.zip"
    truncated.write_bytes((BUNDLES / "good.zip").read_bytes()[:500])
    assert _rejected(truncated, tmp_path).codes == ["invalid_zip"]


def test_other_compression_methods_are_refused(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "bz.zip",
        [("logs/a.log", b"a"), ("manifest.json", _manifest([]))],
        method=zipfile.ZIP_BZIP2,
    )
    assert "unsupported_compression" in _rejected(path, tmp_path).codes


def test_special_file_modes_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "fifo.zip"
    with zipfile.ZipFile(path, "w") as zf:
        fifo = zipfile.ZipInfo("logs/pipe")
        fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
        zf.writestr(fifo, b"")
        reparse = zipfile.ZipInfo("logs/junction")
        reparse.external_attr = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (Windows zip)
        zf.writestr(reparse, b"")
        zf.writestr("manifest.json", _manifest([]))
    assert {"special_file", "reparse_point"} <= set(_rejected(path, tmp_path).codes)


def test_corrupt_member_is_flagged(tmp_path: Path) -> None:
    raw = bytearray((BUNDLES / "good.zip").read_bytes())
    name_len, extra_len = struct.unpack_from("<HH", raw, 26)
    raw[30 + name_len + extra_len + 200] ^= 0xFF  # inside auth.log's deflate stream
    path = tmp_path / "corrupt.zip"
    path.write_bytes(bytes(raw))
    statuses, counts, _ = _open(path, tmp_path)
    assert statuses[0] == "corrupt" and counts["verified"] == 2


def test_manifest_listing_too_many_files(tmp_path: Path) -> None:
    files = [{"path": f"logs/{i}", "sha256": "0" * 64, "size": 1} for i in range(20)]
    path = _zip(tmp_path / "m.zip", [("manifest.json", _manifest(files))])
    assert "manifest_too_many_files" in _rejected(path, tmp_path, max_members=10).codes


# ---------------------------------------------------------------------------------- manifest


def test_manifest_parsing_is_strict_where_it_matters() -> None:
    good = _manifest([{"path": "logs/a", "sha256": "A" * 64, "size": 1}], future_field={"x": 1})
    manifest, digest = parse_manifest(b"\xef\xbb\xbf" + good)  # BOM (PowerShell) accepted
    assert manifest.files[0].sha256 == "a" * 64 and digest
    bad_cases = [
        b"not json",
        b"[]",
        b'{"schema": "dfirbench.triage/1", "schema": "x"}',  # duplicate keys
        _manifest([], schema="dfirbench.triage/2"),
        _manifest([], started_at="2026-01-03T00:00:00"),  # no zone
        _manifest([{"path": "a", "sha256": "0" * 64, "size": 1}] * 2),  # duplicate paths
        _manifest([{"path": "a", "sha256": "xyz", "size": 1}]),
        _manifest([{"path": "a", "sha256": "0" * 64, "size": -1}]),
        _manifest([{"path": "/etc/passwd", "sha256": "0" * 64, "size": 1}]),
        _manifest([{"path": "manifest.json", "sha256": "0" * 64, "size": 1}]),
        b"[" * 100_000 + b"]" * 100_000,  # nesting bomb
    ]
    for data in bad_cases:
        with pytest.raises(ManifestError):
            parse_manifest(data)


def test_manifest_strings_are_cleaned_for_jsonb() -> None:
    manifest, _ = parse_manifest(_manifest([], operator="eve\u0000\ud800", host={"hostname": "h"}))
    assert manifest.operator is not None and "\x00" not in manifest.operator
    manifest.operator.encode("utf-8")  # no lone surrogates left


# ---------------------------------------------------------------------------------- trust


def _collector_hashes() -> set[str]:
    out = set()
    for rel in ("collector/collect_linux.py", "collector/collect-windows.ps1"):
        lf = (REPO / rel).read_bytes().replace(b"\r\n", b"\n")
        out |= {
            hashlib.sha256(lf).hexdigest(),
            hashlib.sha256(lf.replace(b"\n", b"\r\n")).hexdigest(),
        }
    return out


def test_trusted_collector_list_matches_the_scripts() -> None:
    trusted = load_trusted_collectors()
    assert set(trusted) == _collector_hashes(), "run scripts/update-collector-hashes.py"
    assert {v["name"] for v in trusted.values()} == {
        "dfirbench-collect-linux",
        "dfirbench-collect-windows",
    }


def test_collector_trust_statuses(tmp_path: Path) -> None:
    trusted = load_trusted_collectors()
    digest, info = next(iter(trusted.items()))
    base = {"schema": "dfirbench.triage/1", "started_at": "2026-01-03T00:00:00Z", "files": []}

    def trust(collector: dict[str, object]) -> str:
        manifest, _ = parse_manifest(json.dumps({**base, "collector": collector}).encode())
        return str(collector_trust(manifest, trusted)["status"])

    assert trust({"name": info["name"], "version": info["version"], "sha256": digest}) == "trusted"
    assert trust({"name": "other", "version": "9", "sha256": digest}) == "name_mismatch"
    assert trust({"name": info["name"], "version": "1.0.0", "sha256": "1" * 64}) == "unknown"
    assert trust({"name": info["name"], "version": "1.0.0"}) == "no_hash"
    extra = tmp_path / "extra.json"
    extra.write_text(
        json.dumps({"collectors": [{"name": "local", "version": "2", "sha256": "2" * 64}]})
    )
    assert "2" * 64 in load_trusted_collectors(str(extra))
    assert load_trusted_collectors(str(tmp_path / "missing.json")).keys() == trusted.keys()
    assert PACKAGED.is_file()
