# Detection coverage (built-in rule pack)

Generated from `backend/app/detection/builtin/*.yml` by `python -m app.detection.coverage`; do not edit by hand. The live table for the rules enabled in a deployment is `GET /api/v1/rules/coverage`.

## By ATT&CK technique

| Technique | Tactics | Rules |
|---|---|---|
| T1053.005 | execution, persistence, privilege-escalation | DFIR-WIN-0007 |
| T1059.001 | execution | DFIR-WIN-0012 |
| T1070 | defense-evasion | DFIR-AF-0002 |
| T1070.001 | defense-evasion | DFIR-WIN-0001, DFIR-WIN-0002, DFIR-WIN-0027, DFIR-WIN-0030 |
| T1070.002 | defense-evasion | DFIR-AF-0003 |
| T1070.006 | defense-evasion | DFIR-AF-0001, DFIR-WIN-0026 |
| T1078 | defense-evasion, persistence, privilege-escalation, initial-access | DFIR-LNX-0003 |
| T1098 | persistence, privilege-escalation | DFIR-LNX-0011, DFIR-WIN-0009 |
| T1110 | credential-access | DFIR-LNX-0001, DFIR-LNX-0002, DFIR-WIN-0003, DFIR-WIN-0004 |
| T1110.003 | credential-access | DFIR-WIN-0005 |
| T1136.001 | persistence | DFIR-LNX-0004, DFIR-WIN-0008 |
| T1490 | impact | DFIR-WIN-0010, DFIR-WIN-0011 |
| T1543.003 | persistence, privilege-escalation | DFIR-WIN-0006 |
| T1562.002 | defense-evasion | DFIR-WIN-0029 |

## Rules

| Rule | Title | Level | Kind | ATT&CK |
|---|---|---|---|---|
| DFIR-AF-0001 | Timestamps out of order within a log | medium | detector | T1070.006 |
| DFIR-AF-0002 | Logging gap within a source | low | detector | T1070 |
| DFIR-AF-0003 | Log ends long before acquisition | low | detector | T1070.002 |
| DFIR-IOC-0001 | IOC match | high | detector | - |
| DFIR-LNX-0001 | SSH brute force | medium | threshold | T1110 |
| DFIR-LNX-0002 | SSH success after failures | high | sequence | T1110 |
| DFIR-LNX-0003 | Root login over SSH | high | single | T1078 |
| DFIR-LNX-0004 | New Linux user created | medium | single | T1136.001 |
| DFIR-LNX-0011 | Linux user added to a privileged group | high | single | T1098 |
| DFIR-WIN-0001 | Windows Security event log cleared | high | single | T1070.001 |
| DFIR-WIN-0002 | Windows System event log cleared | high | single | T1070.001 |
| DFIR-WIN-0003 | Possible brute-force logons | medium | threshold | T1110 |
| DFIR-WIN-0004 | Successful logon after repeated failures | high | sequence | T1110 |
| DFIR-WIN-0005 | Password spray from one source | high | threshold | T1110.003 |
| DFIR-WIN-0006 | Service installed from an unusual path | high | single | T1543.003 |
| DFIR-WIN-0007 | Scheduled task created | medium | single | T1053.005 |
| DFIR-WIN-0008 | User account created | medium | single | T1136.001 |
| DFIR-WIN-0009 | Account added to a privileged group | high | single | T1098 |
| DFIR-WIN-0010 | Volume shadow copies deleted | critical | single | T1490 |
| DFIR-WIN-0011 | Windows recovery disabled with bcdedit | high | single | T1490 |
| DFIR-WIN-0012 | Encoded PowerShell command | medium | single | T1059.001 |
| DFIR-WIN-0026 | System time changed | low | single | T1070.006 |
| DFIR-WIN-0027 | EVTX record id gap | medium | detector | T1070.001 |
| DFIR-WIN-0029 | Audit policy changed | high | single | T1562.002 |
| DFIR-WIN-0030 | Event log cleared from the command line | high | single | T1070.001 |
