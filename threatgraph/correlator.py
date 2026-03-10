"""
ThreatGraph Correlator
Groups raw events into higher-level attack stages and builds the attack chain.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional
import pandas as pd


# ──────────────────────────────────────────────
# MITRE ATT&CK mapping
# ──────────────────────────────────────────────
MITRE_MAP: dict[str, list[tuple[str, str]]] = {
    "PORT_SCAN":               [("T1046", "Network Service Discovery")],
    "AUTH_FAILED":             [("T1110", "Brute Force")],
    "AUTH_SUCCESS":            [("T1078", "Valid Accounts")],
    "SUDO_EXEC":               [("T1548.003", "Sudo and Sudo Caching")],
    "POWERSHELL_EXEC":         [("T1059.001", "PowerShell")],
    "PROCESS_CREATE":          [("T1059", "Command and Scripting Interpreter")],
    "USER_CREATED":            [("T1136", "Create Account")],
    "PRIVILEGE_ESCALATION":    [("T1548", "Abuse Elevation Control Mechanism")],
    "PERSISTENCE_REGISTRY":    [("T1547.001", "Registry Run Keys")],
    "PERSISTENCE_STARTUP":     [("T1547.001", "Startup Folder")],
    "PERSISTENCE_SCHEDULED_TASK": [("T1053.005", "Scheduled Task")],
    "NETWORK_CONNECT":         [("T1071", "Application Layer Protocol")],
    "C2_BEACON":               [("T1071", "Application Layer Protocol"), ("T1105", "Ingress Tool Transfer")],
    "DATA_EXFIL":              [("T1041", "Exfiltration Over C2 Channel")],
    "FILE_CREATE":             [("T1105", "Ingress Tool Transfer")],
}

# Kill chain stage labels
STAGE_MAP: dict[str, str] = {
    "PORT_SCAN":               "Reconnaissance",
    "AUTH_FAILED":             "Initial Access",
    "AUTH_SUCCESS":            "Initial Access",
    "SUDO_EXEC":               "Privilege Escalation",
    "POWERSHELL_EXEC":         "Execution",
    "PROCESS_CREATE":          "Execution",
    "USER_CREATED":            "Persistence",
    "PRIVILEGE_ESCALATION":    "Privilege Escalation",
    "PERSISTENCE_REGISTRY":    "Persistence",
    "PERSISTENCE_STARTUP":     "Persistence",
    "PERSISTENCE_SCHEDULED_TASK": "Persistence",
    "NETWORK_CONNECT":         "Command & Control",
    "C2_BEACON":               "Command & Control",
    "DATA_EXFIL":              "Exfiltration",
    "FILE_CREATE":             "Defense Evasion",
}

STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Persistence",
    "Defense Evasion",
    "Command & Control",
    "Exfiltration",
]


# ──────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────
@dataclass
class AttackNode:
    node_id: str
    event_type: str
    stage: str
    label: str
    timestamp: pd.Timestamp
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    count: int = 1
    mitre: list[tuple[str, str]] = field(default_factory=list)
    raw_events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "event_type": self.event_type,
            "stage": self.stage,
            "label": self.label,
            "timestamp": str(self.timestamp),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user": self.user,
            "process": self.process,
            "count": self.count,
            "mitre": self.mitre,
        }


@dataclass
class AttackGraph:
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)
    attacker_ip: Optional[str] = None
    victim_ip: Optional[str] = None
    affected_user: Optional[str] = None
    timeline_start: Optional[pd.Timestamp] = None
    timeline_end: Optional[pd.Timestamp] = None
    stages_observed: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
# Correlation helpers
# ──────────────────────────────────────────────
def _count_label(event_type: str, count: int, df_slice: pd.DataFrame) -> str:
    """Human-readable label for a correlated node."""
    if event_type == "AUTH_FAILED":
        users = df_slice["user"].dropna().unique().tolist()
        return f"{count} failed SSH login{'s' if count > 1 else ''} ({', '.join(users[:3])})"
    if event_type == "AUTH_SUCCESS":
        user = df_slice["user"].dropna().iloc[0] if not df_slice["user"].dropna().empty else "unknown"
        ip = df_slice["src_ip"].dropna().iloc[0] if not df_slice["src_ip"].dropna().empty else "unknown"
        return f"Successful login: {user} from {ip}"
    if event_type == "PORT_SCAN":
        return f"Port scan from {df_slice['src_ip'].dropna().iloc[0]}"
    if event_type == "POWERSHELL_EXEC":
        return "Encoded PowerShell execution"
    if event_type == "USER_CREATED":
        user = df_slice["user"].dropna().iloc[0] if not df_slice["user"].dropna().empty else "unknown"
        return f"New account created: {user}"
    if event_type == "PRIVILEGE_ESCALATION":
        return "Privilege escalation (admin group)"
    if event_type == "PERSISTENCE_REGISTRY":
        return "Registry run key added"
    if event_type == "PERSISTENCE_STARTUP":
        return "Startup folder persistence"
    if event_type == "PERSISTENCE_SCHEDULED_TASK":
        return "Scheduled task persistence"
    if event_type == "C2_BEACON":
        dst = df_slice["dst_ip"].dropna().iloc[0] if not df_slice["dst_ip"].dropna().empty else "unknown"
        port_raw = df_slice["port"].dropna().iloc[0] if not df_slice["port"].dropna().empty else None
        port = int(port_raw) if port_raw is not None else "?"
        return f"C2 beacon → {dst}:{port}"
    if event_type == "DATA_EXFIL":
        total = df_slice["bytes_sent"].fillna(0).sum()
        dst = df_slice["dst_ip"].dropna().iloc[0] if not df_slice["dst_ip"].dropna().empty else "unknown"
        mb = total / (1024 * 1024)
        return f"Data exfiltration → {dst} ({mb:.1f} MB)"
    if event_type == "SUDO_EXEC":
        return "Root shell via sudo"
    if event_type == "NETWORK_CONNECT":
        dst = df_slice["dst_ip"].dropna().iloc[0] if not df_slice["dst_ip"].dropna().empty else "unknown"
        return f"Outbound connection → {dst}"
    return f"{event_type} ({count}x)"


# ──────────────────────────────────────────────
# Main correlator
# ──────────────────────────────────────────────
def correlate(df: pd.DataFrame) -> AttackGraph:
    """
    Takes a normalised event DataFrame and returns an AttackGraph.
    Groups events by type (collapsing brute-force floods, etc.)
    and links them into a causal chain.
    """
    graph = AttackGraph()

    if df.empty:
        return graph

    # Detect attacker IP: the src_ip with the most AUTH_FAILED events
    failed = df[df["event_type"] == "AUTH_FAILED"]
    if not failed.empty:
        attacker_ip = failed["src_ip"].value_counts().idxmax()
        graph.attacker_ip = attacker_ip
    else:
        # Fallback: first external src_ip
        external = df[df["src_ip"].notna() & ~df["src_ip"].str.startswith(("192.168.", "10.", "172."))]
        if not external.empty:
            graph.attacker_ip = external["src_ip"].iloc[0]

    # Detect victim / affected user
    success = df[df["event_type"] == "AUTH_SUCCESS"]
    if not success.empty:
        graph.affected_user = success["user"].dropna().iloc[0] if not success["user"].dropna().empty else None

    graph.timeline_start = df["timestamp"].min()
    graph.timeline_end = df["timestamp"].max()

    # ── Collapse events into nodes ──────────────────────────────
    # Priority order: deduplicate within each event_type bucket
    node_order = [
        "PORT_SCAN",
        "AUTH_FAILED",
        "AUTH_SUCCESS",
        "SUDO_EXEC",
        "POWERSHELL_EXEC",
        "PROCESS_CREATE",
        "USER_CREATED",
        "PRIVILEGE_ESCALATION",
        "PERSISTENCE_REGISTRY",
        "PERSISTENCE_STARTUP",
        "PERSISTENCE_SCHEDULED_TASK",
        "FILE_CREATE",
        "NETWORK_CONNECT",
        "C2_BEACON",
        "DATA_EXFIL",
    ]

    seen_types: set[str] = set()

    for etype in node_order:
        subset = df[df["event_type"] == etype]
        if subset.empty:
            continue

        if etype in seen_types:
            continue
        seen_types.add(etype)

        stage = STAGE_MAP.get(etype, "Unknown")
        label = _count_label(etype, len(subset), subset)
        mitre = MITRE_MAP.get(etype, [])

        node = AttackNode(
            node_id=f"node_{len(graph.nodes)}",
            event_type=etype,
            stage=stage,
            label=label,
            timestamp=subset["timestamp"].min(),
            src_ip=subset["src_ip"].dropna().iloc[0] if not subset["src_ip"].dropna().empty else None,
            dst_ip=subset["dst_ip"].dropna().iloc[0] if not subset["dst_ip"].dropna().empty else None,
            user=subset["user"].dropna().iloc[0] if not subset["user"].dropna().empty else None,
            process=subset["process"].dropna().iloc[0] if not subset["process"].dropna().empty else None,
            count=len(subset),
            mitre=mitre,
            raw_events=subset.to_dict("records"),
        )
        graph.nodes.append(node)

    # ── Sort nodes by timestamp ──────────────────────────────────
    graph.nodes.sort(key=lambda n: n.timestamp)

    # ── Build edges (linear chain) ───────────────────────────────
    for i in range(len(graph.nodes) - 1):
        graph.edges.append((graph.nodes[i].node_id, graph.nodes[i + 1].node_id))

    # ── Collect observed stages ──────────────────────────────────
    stage_set = {n.stage for n in graph.nodes}
    graph.stages_observed = [s for s in STAGE_ORDER if s in stage_set]

    return graph


def summarise_for_ai(graph: AttackGraph) -> str:
    """Produces a concise event summary to send to the AI for explanation."""
    lines = ["Detected security events (chronological order):"]
    for node in graph.nodes:
        ts = str(node.timestamp)[:16]
        lines.append(f"  [{ts}] {node.stage}: {node.label}")
        if node.mitre:
            techniques = ", ".join(f"{t[0]} ({t[1]})" for t in node.mitre)
            lines.append(f"           MITRE: {techniques}")

    if graph.attacker_ip:
        lines.append(f"\nAttacker IP: {graph.attacker_ip}")
    if graph.affected_user:
        lines.append(f"Affected user: {graph.affected_user}")
    if graph.timeline_start and graph.timeline_end:
        duration = graph.timeline_end - graph.timeline_start
        lines.append(f"Attack duration: {duration}")

    return "\n".join(lines)
