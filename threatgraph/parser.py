"""
ThreatGraph Log Parser
Parses sysmon, auth, and network logs into normalized event dictionaries.
"""

import re
from datetime import datetime
from typing import Optional
import pandas as pd


# ──────────────────────────────────────────────
# Normalised event schema
# ──────────────────────────────────────────────
def make_event(
    timestamp: datetime,
    source: str,
    event_type: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    user: Optional[str] = None,
    process: Optional[str] = None,
    command: Optional[str] = None,
    port: Optional[int] = None,
    bytes_sent: Optional[int] = None,
    raw: Optional[str] = None,
) -> dict:
    return {
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": user,
        "process": process,
        "command": command,
        "port": port,
        "bytes_sent": bytes_sent,
        "raw": raw,
    }


# ──────────────────────────────────────────────
# Auth log parser
# ──────────────────────────────────────────────
def parse_auth_log(content: str, year: Optional[int] = None) -> list[dict]:
    events = []
    # Use provided year (inferred from other logs) or fall back to current year
    if year is None:
        year = datetime.now().year

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # Jan 15 11:58:01 ...
        ts_match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
        if not ts_match:
            continue
        try:
            ts = datetime.strptime(f"{year} {ts_match.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue

        if "Failed password" in line:
            user_match = re.search(r"Failed password for (\S+) from (\S+)", line)
            if user_match:
                events.append(make_event(
                    timestamp=ts, source="auth.log",
                    event_type="AUTH_FAILED",
                    user=user_match.group(1),
                    src_ip=user_match.group(2),
                    raw=line,
                ))

        elif "Accepted password" in line or "Accepted publickey" in line:
            user_match = re.search(r"Accepted \S+ for (\S+) from (\S+)", line)
            if user_match:
                events.append(make_event(
                    timestamp=ts, source="auth.log",
                    event_type="AUTH_SUCCESS",
                    user=user_match.group(1),
                    src_ip=user_match.group(2),
                    raw=line,
                ))

        elif "new user" in line or "useradd" in line:
            user_match = re.search(r"name=(\S+),", line)
            events.append(make_event(
                timestamp=ts, source="auth.log",
                event_type="USER_CREATED",
                user=user_match.group(1) if user_match else None,
                raw=line,
            ))

        elif "usermod" in line and "sudo" in line:
            events.append(make_event(
                timestamp=ts, source="auth.log",
                event_type="PRIVILEGE_ESCALATION",
                raw=line,
            ))

        elif "sudo" in line and "COMMAND" in line:
            user_match = re.search(r"sudo\[\d+\]:\s+(\S+)\s+:", line)
            cmd_match = re.search(r"COMMAND=(.+)$", line)
            events.append(make_event(
                timestamp=ts, source="auth.log",
                event_type="SUDO_EXEC",
                user=user_match.group(1) if user_match else None,
                command=cmd_match.group(1) if cmd_match else None,
                raw=line,
            ))

    return events


# ──────────────────────────────────────────────
# Sysmon log parser
# ──────────────────────────────────────────────
def parse_sysmon_log(content: str) -> list[dict]:
    events = []

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if not ts_match:
            continue
        try:
            ts = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

        def field(key: str) -> Optional[str]:
            m = re.search(rf"{key}=([^\s]+)", line)
            return m.group(1) if m else None

        event_id = field("EventID")
        image = field("Image") or ""
        user = field("User")
        cmd = field("CommandLine")
        dst_ip = field("DestinationIp")
        dst_port_raw = field("DestinationPort")
        dst_port = int(dst_port_raw) if dst_port_raw and dst_port_raw.isdigit() else None
        src_ip = field("SourceIp")
        bytes_sent_raw = field("BytesSent")
        bytes_sent = int(bytes_sent_raw) if bytes_sent_raw and bytes_sent_raw.isdigit() else None
        target_file = field("TargetFilename")

        proc_name = image.split("\\")[-1] if image else None

        if event_id == "1":  # ProcessCreate
            # Classify by image / command
            if cmd and ("net user" in cmd and "/add" in cmd):
                etype = "USER_CREATED"
            elif cmd and "localgroup administrators" in cmd:
                etype = "PRIVILEGE_ESCALATION"
            elif cmd and ("reg add" in cmd and "Run" in cmd):
                etype = "PERSISTENCE_REGISTRY"
            elif cmd and "schtasks" in cmd:
                etype = "PERSISTENCE_SCHEDULED_TASK"
            elif proc_name and "powershell" in proc_name.lower():
                etype = "POWERSHELL_EXEC"
            else:
                etype = "PROCESS_CREATE"

            events.append(make_event(
                timestamp=ts, source="sysmon.log",
                event_type=etype,
                user=user, process=proc_name, command=cmd,
                raw=line,
            ))

        elif event_id == "3":  # NetworkConnect
            etype = "DATA_EXFIL" if (bytes_sent and bytes_sent > 1_000_000) else "NETWORK_CONNECT"
            events.append(make_event(
                timestamp=ts, source="sysmon.log",
                event_type=etype,
                src_ip=src_ip, dst_ip=dst_ip, port=dst_port,
                process=proc_name, bytes_sent=bytes_sent,
                raw=line,
            ))

        elif event_id == "11":  # FileCreate
            etype = "PERSISTENCE_STARTUP" if target_file and "Startup" in target_file else "FILE_CREATE"
            events.append(make_event(
                timestamp=ts, source="sysmon.log",
                event_type=etype,
                process=proc_name, command=target_file,
                raw=line,
            ))

    return events


# ──────────────────────────────────────────────
# Network log parser
# ──────────────────────────────────────────────
def parse_network_log(content: str) -> list[dict]:
    events = []

    port_scan_candidates: dict[str, list] = {}

    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue

        ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if not ts_match:
            continue
        try:
            ts = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

        def field(key: str) -> Optional[str]:
            m = re.search(rf"{key}=([^\s]+)", line)
            return m.group(1) if m else None

        src = field("SRC")
        dst = field("DST")
        dpt_raw = field("DPT")
        dpt = int(dpt_raw) if dpt_raw and dpt_raw.isdigit() else None
        flags = field("FLAGS")
        bytes_val_raw = field("BYTES")
        bytes_val = int(bytes_val_raw) if bytes_val_raw and bytes_val_raw.isdigit() else None
        proto = field("PROTO")

        if flags == "SYN" and src:
            port_scan_candidates.setdefault(src, []).append((ts, dst, dpt))

        if bytes_val and bytes_val > 1_000_000:
            events.append(make_event(
                timestamp=ts, source="network.log",
                event_type="DATA_EXFIL",
                src_ip=src, dst_ip=dst, port=dpt,
                bytes_sent=bytes_val,
                raw=line,
            ))
        elif dpt in (4444, 1337, 9001, 31337):
            events.append(make_event(
                timestamp=ts, source="network.log",
                event_type="C2_BEACON",
                src_ip=src, dst_ip=dst, port=dpt,
                raw=line,
            ))
        elif flags == "ACK" and bytes_val:
            events.append(make_event(
                timestamp=ts, source="network.log",
                event_type="NETWORK_CONNECT",
                src_ip=src, dst_ip=dst, port=dpt,
                bytes_sent=bytes_val,
                raw=line,
            ))

    # Detect port scans: ≥8 SYN packets from same IP in short window
    for ip, scans in port_scan_candidates.items():
        if len(scans) >= 8:
            first_ts = scans[0][0]
            events.append(make_event(
                timestamp=first_ts, source="network.log",
                event_type="PORT_SCAN",
                src_ip=ip,
                dst_ip=scans[0][1],
                raw=f"Port scan detected: {len(scans)} SYN packets from {ip}",
            ))

    return events


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────
def parse_logs(files: dict[str, str]) -> pd.DataFrame:
    """
    files: dict mapping filename -> file content string
    Returns a sorted DataFrame of all parsed events.
    """
    all_events: list[dict] = []

    # First pass: infer year from sysmon or network logs (they include full timestamps)
    inferred_year: Optional[int] = None
    for filename, content in files.items():
        name = filename.lower()
        if "sysmon" in name or "network" in name or "net" in name:
            m = re.search(r"(\d{4})-\d{2}-\d{2}", content)
            if m:
                inferred_year = int(m.group(1))
                break

    # Second pass: parse all files
    for filename, content in files.items():
        name = filename.lower()
        if "sysmon" in name:
            all_events.extend(parse_sysmon_log(content))
        elif "auth" in name:
            all_events.extend(parse_auth_log(content, year=inferred_year))
        elif "network" in name or "net" in name:
            all_events.extend(parse_network_log(content))

    if not all_events:
        return pd.DataFrame()

    df = pd.DataFrame(all_events)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df
