"""Volatility 3 wrapper (spec decision 7). The parser itself follows in a later commit."""

from __future__ import annotations

# Allowlisted plugins per OS (job parameter ``plugins``); anything else is rejected with 422.
VOLATILITY_PLUGINS: dict[str, frozenset[str]] = {
    "windows": frozenset(
        {
            "info",
            "pslist",
            "psscan",
            "pstree",
            "cmdline",
            "netscan",
            "netstat",
            "dlllist",
            "svcscan",
            "malfind",
        }
    ),
    "linux": frozenset({"pslist", "pstree", "bash", "lsmod", "sockstat", "malfind"}),
}
DEFAULT_PLUGINS: dict[str, tuple[str, ...]] = {
    "windows": ("info", "pslist", "cmdline", "netscan"),
    "linux": ("pslist", "bash"),
}
