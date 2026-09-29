"""MITRE ATT&CK technique ids: format validation and a small technique -> tactic table.

Only the format is validated (``T1234`` or ``T1234.001``); the table covers the techniques the
starter rules use plus common neighbours, and is used for the case-risk tactic bonus and the ATT&CK
view. Unknown (well-formed) techniques are accepted and simply contribute no tactic.
"""

from __future__ import annotations

import re
from typing import Literal

TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")

TACTICS: dict[str, tuple[str, ...]] = {
    "T1003": ("credential-access",),
    "T1005": ("collection",),
    "T1016": ("discovery",),
    "T1021": ("lateral-movement",),
    "T1027": ("defense-evasion",),
    "T1036": ("defense-evasion",),
    "T1041": ("exfiltration",),
    "T1047": ("execution",),
    "T1048": ("exfiltration",),
    "T1053": ("execution", "persistence", "privilege-escalation"),
    "T1055": ("defense-evasion", "privilege-escalation"),
    "T1057": ("discovery",),
    "T1059": ("execution",),
    "T1070": ("defense-evasion",),
    "T1071": ("command-and-control",),
    "T1078": ("defense-evasion", "persistence", "privilege-escalation", "initial-access"),
    "T1082": ("discovery",),
    "T1087": ("discovery",),
    "T1090": ("command-and-control",),
    "T1098": ("persistence", "privilege-escalation"),
    "T1105": ("command-and-control",),
    "T1110": ("credential-access",),
    "T1112": ("defense-evasion",),
    "T1133": ("persistence", "initial-access"),
    "T1136": ("persistence",),
    "T1140": ("defense-evasion",),
    "T1190": ("initial-access",),
    "T1204": ("execution",),
    "T1218": ("defense-evasion",),
    "T1219": ("command-and-control",),
    "T1485": ("impact",),
    "T1486": ("impact",),
    "T1489": ("impact",),
    "T1490": ("impact",),
    "T1543": ("persistence", "privilege-escalation"),
    "T1546": ("persistence", "privilege-escalation"),
    "T1547": ("persistence", "privilege-escalation"),
    "T1548": ("privilege-escalation", "defense-evasion"),
    "T1550": ("defense-evasion", "lateral-movement"),
    "T1552": ("credential-access",),
    "T1555": ("credential-access",),
    "T1558": ("credential-access",),
    "T1562": ("defense-evasion",),
    "T1566": ("initial-access",),
    "T1568": ("command-and-control",),
    "T1569": ("execution",),
    "T1570": ("lateral-movement",),
    "T1572": ("command-and-control",),
    "T1574": ("persistence", "privilege-escalation", "defense-evasion"),
}


def is_technique(value: str) -> bool:
    return isinstance(value, str) and bool(TECHNIQUE.fullmatch(value))


def tactics_of(technique: str) -> tuple[str, ...]:
    return TACTICS.get(technique.split(".", 1)[0], ())


def tactics_for(techniques: list[str] | tuple[str, ...] | set[str]) -> set[str]:
    out: set[str] = set()
    for technique in techniques:
        out.update(tactics_of(technique))
    return out


# Alert/rule severity levels (the ``severity`` enum values; kept here so detection stays DB-free).
Level = Literal["info", "low", "medium", "high", "critical"]
LEVELS: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
