"""Process tree builder (guide 12.6): guid and pid parents, PID reuse, cycles, caps, flags."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.analysis.proctree import ProcEvent, basename, build_tree, norm_guid

T0 = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)


def pe(n: int, pid: int, ppid: int | None, name: str, **kw: object) -> ProcEvent:
    return ProcEvent(
        event_id=f"e{n}", ts=T0 + timedelta(seconds=n), pid=pid, ppid=ppid, name=name,
        created=kw.pop("created", True), **kw,  # type: ignore[arg-type]
    )  # fmt: skip


def by_name(tree: object) -> dict[str, object]:
    return {n.name: n for n in tree.nodes}  # type: ignore[attr-defined]


def test_helpers() -> None:
    assert basename("C:\\Windows\\System32\\CMD.EXE") == "cmd.exe"
    assert basename("/usr/sbin/sshd") == "sshd" and basename(None) is None
    assert norm_guid("{ABCDEFAB-0000-1111-2222-333344445555}") == (
        "abcdefab-0000-1111-2222-333344445555"
    )
    assert norm_guid("{00000000-0000-0000-0000-000000000000}") is None
    assert norm_guid("nope") is None and norm_guid(5) is None


def test_guid_chain_and_suspicious_pair() -> None:
    g = "{%s-0000-0000-0000-000000000000}"
    tree = build_tree(
        [
            pe(1, 10, 4, "explorer.exe", guid=g % "aaaaaaaa"),
            pe(2, 20, 10, "WINWORD.EXE", guid=g % "bbbbbbbb", parent_guid=g % "aaaaaaaa"),
            pe(3, 30, 20, "powershell.exe", guid=g % "cccccccc", parent_guid=g % "bbbbbbbb"),
        ]
    )
    names = by_name(tree)
    ps, word, explorer = names["powershell.exe"], names["winword.exe"], names["explorer.exe"]
    assert ps.parent == word.key and word.parent == explorer.key  # type: ignore[attr-defined]
    assert "suspicious_parent" in ps.flags  # type: ignore[attr-defined]
    root = tree.nodes[0]
    assert root.kind == "synthetic" and root.pid == 4 and explorer.parent == root.key  # type: ignore[attr-defined]
    assert [n.depth for n in tree.nodes] == [0, 1, 2, 3]  # DFS pre-order


def test_pid_reuse_picks_latest_earlier_process() -> None:
    tree = build_tree(
        [
            pe(1, 1, None, "init"),
            pe(2, 500, 1, "cmd.exe"),
            pe(3, 500, None, "cmd.exe", created=False),  # observed: explained by the create
            pe(5, 500, 1, "rundll32.exe"),
            pe(6, 600, 500, "child.exe"),
            pe(0, 600, 500, "early.exe"),  # before any pid 500: synthetic parent
        ]
    )
    names = by_name(tree)
    keys = {n.key: n for n in tree.nodes}
    assert keys[names["child.exe"].parent].name == "rundll32.exe"  # type: ignore[attr-defined]
    assert keys[names["early.exe"].parent].kind == "synthetic"  # type: ignore[attr-defined]
    assert sum(1 for n in tree.nodes if n.name == "cmd.exe") == 1


def test_cycles_are_broken() -> None:
    g = "{%s-0000-0000-0000-000000000000}"
    tree = build_tree(
        [
            pe(1, 1, 2, "a.exe", guid=g % "11111111", parent_guid=g % "22222222"),
            pe(1, 2, 1, "b.exe", guid=g % "22222222", parent_guid=g % "11111111"),
            pe(2, 3, 3, "self.exe", guid=g % "33333333", parent_guid=g % "33333333"),
        ]
    )
    assert tree.cycles_broken == 1
    assert len(tree.nodes) == 3 and len(tree.roots) == 2
    assert any("cycle_broken" in n.flags for n in tree.nodes)


def test_depth_and_node_caps() -> None:
    chain = [pe(i, 100 + i, 100 + i - 1 if i else None, f"p{i}.exe") for i in range(50)]
    tree = build_tree(chain, max_depth=5)
    assert len(tree.nodes) == 6 and tree.depth_capped == 44
    assert all(n.depth <= 5 for n in tree.nodes)
    assert all(c in {n.key for n in tree.nodes} for n in tree.nodes for c in n.children)
    small = build_tree(chain, max_nodes=10)
    assert small.truncated and len(small.nodes) <= 10


def test_observed_processes_without_creates() -> None:
    tree = build_tree(
        [
            pe(1, 1021, None, "sshd", created=False),
            pe(2, 1021, None, "sshd", created=False),
            pe(3, 2200, None, "sshd", created=False),
        ]
    )
    assert [n.kind for n in tree.nodes] == ["observed", "observed"]
    assert len(tree.roots) == 2
