"""External engine runner and wrappers (spec decision 9), driven by fake binaries (no Docker)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from app.core.exceptions import AppError
from app.parsers.base import ParserInputError, ToolConfig
from app.parsers.tools import (
    ToolFailedError,
    ToolMissingError,
    ToolOutputLimitError,
    ToolTimeoutError,
    clean_env,
    find_tool,
    image_tool_versions,
    run_tool,
)
from app.services.jobs import validate_params
from tests.unit.deep_helpers import BIN, context, make_tool, run


def noop() -> None:
    return None


@pytest.fixture
def tools(tmp_path: Path) -> Path:
    return tmp_path / "tools"


def test_missing_engine_fails_with_a_clear_message(tmp_path: Path, tools: Path) -> None:
    tools.mkdir()
    cfg = ToolConfig(search_path=str(tools))
    with pytest.raises(ToolMissingError, match="'zeek' is not installed in this worker image"):
        find_tool("zeek", cfg, optional_note="optional engine")
    work = tmp_path / "work"
    work.mkdir()
    for parser, fixture in (
        ("zeek", "capture.pcap"),
        ("tsk_fs", "fat12.img"),
        ("volatility", "fat12.img"),
    ):
        with pytest.raises(ParserInputError, match="not installed in this worker image"):
            run(parser, context(BIN / fixture, tools=cfg, work_dir=work))


def test_wrappers_need_a_work_dir(tools: Path) -> None:
    make_tool(tools, "zeek")
    with pytest.raises(ParserInputError, match="work directory"):
        run("zeek", context(BIN / "capture.pcap", tools=ToolConfig(search_path=str(tools))))


def test_timeout_kills_the_engine(tmp_path: Path, tools: Path) -> None:
    make_tool(tools, "sleeper", "sleep")
    cfg = ToolConfig(search_path=str(tools), timeout_s=1)
    started = time.monotonic()
    with pytest.raises(ToolTimeoutError):
        run_tool(
            [find_tool("sleeper", cfg)],
            cwd=tmp_path / "w",
            stdout=tmp_path / "out.txt",
            cfg=cfg,
            heartbeat=noop,
        )
    assert time.monotonic() - started < 20


def test_output_cap_kills_the_engine(tmp_path: Path, tools: Path) -> None:
    make_tool(tools, "flooder", "flood")
    cfg = ToolConfig(search_path=str(tools), timeout_s=60, max_output_bytes=512 * 1024)
    with pytest.raises(ToolOutputLimitError):
        run_tool(
            [find_tool("flooder", cfg)],
            cwd=tmp_path / "w",
            stdout=tmp_path / "out.txt",
            cfg=cfg,
            heartbeat=noop,
        )


def test_cancellation_via_heartbeat_kills_the_engine(tmp_path: Path, tools: Path) -> None:
    make_tool(tools, "sleeper", "sleep")
    cfg = ToolConfig(search_path=str(tools), timeout_s=60)

    class CancelledError(Exception):
        pass

    def heartbeat() -> None:
        raise CancelledError

    started = time.monotonic()
    with pytest.raises(CancelledError):
        run_tool(
            [find_tool("sleeper", cfg)],
            cwd=tmp_path / "w",
            stdout=tmp_path / "out.txt",
            cfg=cfg,
            heartbeat=heartbeat,
        )
    assert time.monotonic() - started < 20


def test_engine_gets_a_clean_environment(
    tmp_path: Path, tools: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("S3_SECRET_KEY", "secret")
    make_tool(tools, "envdump")
    cfg = ToolConfig(search_path=str(tools))
    result = run_tool(
        [find_tool("envdump", cfg)],
        cwd=tmp_path / "w",
        stdout=tmp_path / "env.json",
        cfg=cfg,
        heartbeat=noop,
    )
    assert result.returncode == 0
    names = set(json.loads((tmp_path / "env.json").read_text()))
    assert "DATABASE_URL" not in names and "S3_SECRET_KEY" not in names
    assert {"PATH", "HOME", "TMPDIR", "TZ"} <= {n.upper() for n in names}
    env = clean_env(tmp_path, cfg)
    assert env["TZ"] == "UTC" and env["HOME"] == str(tmp_path)


def test_argv_must_be_absolute(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        run_tool(
            ["fls", "-V"], cwd=tmp_path, stdout=tmp_path / "o", cfg=ToolConfig(), heartbeat=noop
        )


def test_tsk_without_any_readable_file_system_fails(tmp_path: Path, tools: Path) -> None:
    make_tool(tools, "mmls", "mmls_none")
    make_tool(tools, "fls", "vol")  # 'vol' fake without --offline exits 2 -> fls "fails"
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ToolFailedError, match="fls could not read a file system"):
        run(
            "tsk_fs",
            context(BIN / "fat12.img", tools=ToolConfig(search_path=str(tools)), work_dir=work),
        )


def test_volatility_all_plugins_failing_fails_the_job(tmp_path: Path, tools: Path) -> None:
    make_tool(tools, "vol")
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ToolFailedError, match="Unsatisfied requirement"):
        run(
            "volatility",
            context(
                BIN / "fat12.img",
                params={"os": "windows", "plugins": ["malfind"]},
                tools=ToolConfig(search_path=str(tools)),
                work_dir=work,
            ),
        )


def test_volatility_params_are_allowlisted() -> None:
    assert validate_params(
        "volatility", {"os": "linux", "plugins": ["pslist", "bash", "pslist"]}
    ) == {
        "os": "linux",
        "plugins": ["bash", "pslist"],
    }
    for bad in (
        {"os": "macos"},
        {"os": ["windows"]},
        {"plugins": ["windows.pslist; rm -rf /"]},
        {"plugins": "pslist"},
        {"plugins": []},
        {"os": "linux", "plugins": ["netscan"]},
        {"symbols": "/tmp"},
    ):
        with pytest.raises(AppError) as err:
            validate_params("volatility", bad)
        assert err.value.status_code == 422
    assert validate_params("tsk_fs", {"timezone": "Europe/Berlin"}) == {"timezone": "Europe/Berlin"}
    with pytest.raises(AppError):
        validate_params("tsk_fs", {"timezone": "Mars/Base"})


def test_image_tool_versions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listing = tmp_path / "tool-versions.txt"
    listing.write_text("dfirbench worker toolchain\nsleuthkit 4.11.1+dfsg-1\nvolatility3 2.28.2\n")
    monkeypatch.setenv("DFIR_TOOL_VERSIONS", str(listing))
    assert image_tool_versions(["sleuthkit", "zeek"]) == {"sleuthkit": "4.11.1+dfsg-1"}
    monkeypatch.delenv("DFIR_TOOL_VERSIONS")
    assert image_tool_versions(["sleuthkit"]) == {}
