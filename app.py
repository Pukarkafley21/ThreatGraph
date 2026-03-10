"""
ThreatGraph — Autonomous Threat Investigation Engine
Streamlit frontend
"""

import os
import io
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from threatgraph.parser import parse_logs
from threatgraph.correlator import correlate
from threatgraph.graph_builder import build_graph_figure
from threatgraph.ai_explainer import explain_attack
from threatgraph.report_generator import generate_report

# ─────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatGraph",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Custom CSS  — dark terminal aesthetic
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@300;400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0f172a;
    color: #e2e8f0;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #0f172a;
    border-right: 1px solid #1e293b;
}

/* Cards */
.threat-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin: 0.5rem 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
}

.threat-card-header {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-bottom: 0.4rem;
}

/* Stage badge colours */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    letter-spacing: 0.05em;
}
.badge-recon      { background: #451a03; color: #f59e0b; }
.badge-initial    { background: #450a0a; color: #ef4444; }
.badge-execution  { background: #431407; color: #f97316; }
.badge-priv       { background: #3b0764; color: #a855f7; }
.badge-persist    { background: #2e1065; color: #8b5cf6; }
.badge-evasion    { background: #1e1b4b; color: #6366f1; }
.badge-c2         { background: #0c4a6e; color: #0ea5e9; }
.badge-exfil      { background: #022c22; color: #10b981; }

/* Metric boxes */
.metric-row {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin: 1rem 0;
}
.metric-box {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 1rem 1.5rem;
    flex: 1;
    min-width: 130px;
    text-align: center;
}
.metric-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2rem;
    font-weight: 700;
    color: #f1f5f9;
}
.metric-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-top: 4px;
}

/* Severity */
.sev-critical { color: #ef4444; font-weight: 700; }
.sev-high     { color: #f97316; font-weight: 700; }
.sev-medium   { color: #f59e0b; font-weight: 700; }
.sev-low      { color: #10b981; font-weight: 700; }

/* Monospace blocks */
.mono-block {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 1rem 1.2rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #94a3b8;
    white-space: pre-wrap;
    word-break: break-word;
}

/* MITRE table */
.mitre-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid #1e293b;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
}
.mitre-id {
    background: #0c4a6e;
    color: #38bdf8;
    padding: 2px 8px;
    border-radius: 4px;
    min-width: 100px;
    text-align: center;
    font-weight: 600;
}

/* Divider */
hr { border-color: #1e293b; }

/* Hide streamlit branding */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
STAGE_BADGE_CLASS = {
    "Reconnaissance":      "badge-recon",
    "Initial Access":      "badge-initial",
    "Execution":           "badge-execution",
    "Privilege Escalation":"badge-priv",
    "Persistence":         "badge-persist",
    "Defense Evasion":     "badge-evasion",
    "Command & Control":   "badge-c2",
    "Exfiltration":        "badge-exfil",
}


def stage_badge(stage: str) -> str:
    cls = STAGE_BADGE_CLASS.get(stage, "badge-c2")
    return f'<span class="badge {cls}">{stage}</span>'


def severity_html(sev: str) -> str:
    cls = f"sev-{sev.lower()}" if sev.lower() in ("critical", "high", "medium", "low") else ""
    return f'<span class="{cls}">{sev}</span>'


def load_sample_logs() -> dict[str, str]:
    sample_dir = os.path.join(os.path.dirname(__file__), "sample_logs")
    files = {}
    for fname in ("sysmon.log", "auth.log", "network.log"):
        path = os.path.join(sample_dir, fname)
        if os.path.exists(path):
            with open(path, "r") as f:
                files[fname] = f.read()
    return files


# ─────────────────────────────────────────────
# Session state init
# ─────────────────────────────────────────────
for key in ("attack_graph", "ai_result", "events_df", "report_md"):
    if key not in st.session_state:
        st.session_state[key] = None


# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🕵️ ThreatGraph")
    st.markdown("<small style='color:#475569'>Autonomous Threat Investigation Engine</small>", unsafe_allow_html=True)
    st.markdown("---")

    st.markdown("### Upload Logs")
    uploaded_files = st.file_uploader(
        "Drop sysmon.log, auth.log, network.log",
        type=["log", "txt", "csv"],
        accept_multiple_files=True,
        help="Supported: sysmon, auth, network/firewall logs",
    )

    st.markdown("---")
    st.markdown("### OpenAI API Key")
    api_key = st.text_input(
        "sk-...",
        type="password",
        help="Optional. Without a key, rule-based analysis is used.",
        placeholder="sk-... (optional)",
    )

    st.markdown("---")
    use_sample = st.button("🧪 Load Sample Logs", use_container_width=True)
    analyse_btn = st.button("🔍 Analyse Logs", type="primary", use_container_width=True)
    if st.session_state.attack_graph:
        clear_btn = st.button("🗑 Clear Results", use_container_width=True)
        if clear_btn:
            for key in ("attack_graph", "ai_result", "events_df", "report_md"):
                st.session_state[key] = None
            st.rerun()

    st.markdown("---")
    st.markdown("""
<small style='color:#475569;font-family:JetBrains Mono,monospace;font-size:0.72rem;'>
v1.0 · <a href='https://github.com/Pukarkafley21/ThreatGraph' target='_blank' style='color:#38bdf8;'>github.com/Pukarkafley21/ThreatGraph</a><br>
MIT License
</small>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Analysis trigger
# ─────────────────────────────────────────────
files_to_process: dict[str, str] = {}

if use_sample:
    files_to_process = load_sample_logs()
    if not files_to_process:
        st.sidebar.error("Sample logs not found — check sample_logs/ directory.")

elif analyse_btn and uploaded_files:
    for uf in uploaded_files:
        content = uf.read().decode("utf-8", errors="replace")
        files_to_process[uf.name] = content

if files_to_process:
    with st.spinner("Parsing logs…"):
        df = parse_logs(files_to_process)
        st.session_state.events_df = df

    if df.empty:
        st.error("No parseable events found in the uploaded files.")
    else:
        with st.spinner("Correlating events and building attack graph…"):
            graph = correlate(df)
            st.session_state.attack_graph = graph

        with st.spinner("Running AI analysis…"):
            ai_result = explain_attack(graph, api_key=api_key or None)
            st.session_state.ai_result = ai_result

        with st.spinner("Generating report…"):
            report_md = generate_report(graph, ai_result)
            st.session_state.report_md = report_md

        st.rerun()


# ─────────────────────────────────────────────
# Main content
# ─────────────────────────────────────────────
if not st.session_state.attack_graph:
    # ── Landing screen ───────────────────────
    st.markdown("""
<div style='text-align:center;padding:4rem 2rem 2rem;'>
  <h1 style='font-family:JetBrains Mono,monospace;font-size:2.8rem;font-weight:700;
             background:linear-gradient(135deg,#ef4444,#f97316,#f59e0b);
             -webkit-background-clip:text;-webkit-text-fill-color:transparent;
             margin-bottom:0.5rem;'>
    ThreatGraph
  </h1>
  <p style='color:#64748b;font-size:1.1rem;font-family:Inter,sans-serif;margin-bottom:3rem;'>
    Upload logs. Reconstruct attacks. Visualise the kill chain.
  </p>
</div>
""", unsafe_allow_html=True)

    col1, col2, col3, col4, col5 = st.columns(5)
    steps = [
        ("📥", "Upload Logs", "sysmon · auth · network"),
        ("🔍", "Parse & Correlate", "events grouped automatically"),
        ("🕸️", "Attack Graph", "visual kill chain"),
        ("🤖", "AI Explanation", "plain-english narrative"),
        ("📄", "Download Report", "full incident report"),
    ]
    for col, (icon, title, sub) in zip([col1, col2, col3, col4, col5], steps):
        col.markdown(f"""
<div class='threat-card' style='text-align:center;'>
  <div style='font-size:1.8rem;margin-bottom:0.5rem;'>{icon}</div>
  <div style='font-weight:600;color:#e2e8f0;margin-bottom:0.2rem;'>{title}</div>
  <div style='color:#64748b;font-size:0.78rem;'>{sub}</div>
</div>
""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.info("👈 Upload log files in the sidebar, or click **Load Sample Logs** to see a demo.")
    st.stop()


# ─────────────────────────────────────────────
# Results view
# ─────────────────────────────────────────────
graph = st.session_state.attack_graph
ai_result = st.session_state.ai_result or {}
df: pd.DataFrame = st.session_state.events_df

severity = ai_result.get("severity", "Unknown")
attack_type = ai_result.get("attack_type", "Unknown")

# ── Header ──────────────────────────────────
st.markdown(f"""
<h2 style='font-family:JetBrains Mono,monospace;font-weight:700;color:#f1f5f9;margin-bottom:0;'>
  Attack Chain Detected
</h2>
<p style='color:#64748b;margin-top:0.2rem;'>
  {severity_html(severity)} severity &nbsp;·&nbsp; {attack_type}
  &nbsp;·&nbsp; {str(graph.timeline_start)[:19] if graph.timeline_start else '?'}
  → {str(graph.timeline_end)[:19] if graph.timeline_end else '?'}
</p>
""", unsafe_allow_html=True)

# ── Metrics row ──────────────────────────────
total_events = len(df) if df is not None else 0
unique_stages = len(graph.stages_observed)
mitre_count = len({t[0] for n in graph.nodes for t in n.mitre})
chain_len = len(graph.nodes)

st.markdown(f"""
<div class='metric-row'>
  <div class='metric-box'>
    <div class='metric-value'>{total_events}</div>
    <div class='metric-label'>Raw Events</div>
  </div>
  <div class='metric-box'>
    <div class='metric-value'>{chain_len}</div>
    <div class='metric-label'>Chain Nodes</div>
  </div>
  <div class='metric-box'>
    <div class='metric-value'>{unique_stages}</div>
    <div class='metric-label'>Kill Chain Stages</div>
  </div>
  <div class='metric-box'>
    <div class='metric-value'>{mitre_count}</div>
    <div class='metric-label'>MITRE Techniques</div>
  </div>
  <div class='metric-box'>
    <div class='metric-value' style='font-size:1.1rem;color:#ef4444;'>{graph.attacker_ip or 'Unknown'}</div>
    <div class='metric-label'>Attacker IP</div>
  </div>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ── Tabs ─────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🕸️ Attack Graph",
    "⛓️ Attack Chain",
    "🛡️ MITRE ATT&CK",
    "🤖 AI Analysis",
    "📄 Report",
])

# ── Tab 1: Attack Graph ──────────────────────
with tab1:
    fig = build_graph_figure(graph)
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Graph Legend")
    legend_cols = st.columns(4)
    stage_color_map = {
        "Reconnaissance": "#f59e0b",
        "Initial Access": "#ef4444",
        "Execution": "#f97316",
        "Privilege Escalation": "#a855f7",
        "Persistence": "#8b5cf6",
        "Defense Evasion": "#6366f1",
        "Command & Control": "#0ea5e9",
        "Exfiltration": "#10b981",
    }
    items = list(stage_color_map.items())
    for i, col in enumerate(legend_cols):
        for stage, color in items[i * 2:(i + 1) * 2]:
            col.markdown(
                f"<span style='color:{color};'>●</span> <small>{stage}</small>",
                unsafe_allow_html=True,
            )


# ── Tab 2: Attack Chain ──────────────────────
with tab2:
    st.markdown("#### Step-by-step attack reconstruction")
    for i, node in enumerate(graph.nodes, 1):
        badge = stage_badge(node.stage)
        mitre_tags = " ".join(
            f'<code style="background:#0c4a6e;color:#38bdf8;padding:1px 6px;border-radius:3px;">{t[0]}</code>'
            for t in node.mitre
        )
        ts = str(node.timestamp)[:19]
        detail_parts = []
        if node.src_ip:
            detail_parts.append(f"src: <b>{node.src_ip}</b>")
        if node.dst_ip:
            detail_parts.append(f"dst: <b>{node.dst_ip}</b>")
        if node.user:
            detail_parts.append(f"user: <b>{node.user}</b>")
        if node.count > 1:
            detail_parts.append(f"×{node.count}")
        details = " &nbsp;|&nbsp; ".join(detail_parts)

        st.markdown(f"""
<div class='threat-card'>
  <div class='threat-card-header'>{i:02d} &nbsp;·&nbsp; {ts}</div>
  <div style='display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;'>
    {badge}
    <span style='color:#f1f5f9;font-size:0.9rem;font-weight:500;'>{node.label}</span>
  </div>
  <div style='margin-top:0.5rem;color:#64748b;font-size:0.78rem;'>{details}</div>
  <div style='margin-top:0.4rem;'>{mitre_tags}</div>
</div>
""", unsafe_allow_html=True)

        if i < len(graph.nodes):
            st.markdown(
                "<div style='text-align:left;padding-left:2rem;color:#334155;font-size:1.2rem;'>↓</div>",
                unsafe_allow_html=True,
            )


# ── Tab 3: MITRE ATT&CK ─────────────────────
with tab3:
    st.markdown("#### Observed Techniques")
    seen: set[str] = set()
    for node in graph.nodes:
        for tid, tname in node.mitre:
            if tid in seen:
                continue
            seen.add(tid)
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            st.markdown(f"""
<div class='mitre-row'>
  <span class='mitre-id'>{tid}</span>
  <span style='color:#e2e8f0;flex:1;'>{tname}</span>
  <span style='color:#64748b;font-size:0.75rem;'>{node.stage}</span>
  <a href='{url}' target='_blank' style='color:#38bdf8;font-size:0.75rem;'>→ ATT&CK</a>
</div>
""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### Kill Chain Coverage")
    all_stages = [
        "Reconnaissance", "Initial Access", "Execution",
        "Privilege Escalation", "Persistence", "Defense Evasion",
        "Command & Control", "Exfiltration",
    ]
    observed_set = set(graph.stages_observed)
    cols = st.columns(len(all_stages))
    for col, stage in zip(cols, all_stages):
        observed = stage in observed_set
        color = stage_color_map.get(stage, "#6b7280") if observed else "#1e293b"
        text_color = "#0f172a" if observed else "#334155"
        border = f"2px solid {stage_color_map.get(stage, '#6b7280')}" if observed else "1px solid #334155"
        col.markdown(f"""
<div style='background:{color};border:{border};border-radius:6px;
            padding:0.5rem;text-align:center;'>
  <div style='font-size:0.65rem;font-weight:600;color:{"#0f172a" if observed else "#475569"};
              font-family:JetBrains Mono,monospace;'>{stage}</div>
</div>
""", unsafe_allow_html=True)


# ── Tab 4: AI Analysis ───────────────────────
with tab4:
    explanation = ai_result.get("explanation", "No analysis available.")
    recommendations = ai_result.get("recommendations", [])

    col_a, col_b = st.columns([3, 2])
    with col_a:
        st.markdown("#### Threat Explanation")
        st.markdown(f'<div class="mono-block">{explanation}</div>', unsafe_allow_html=True)

    with col_b:
        st.markdown("#### Recommended Actions")
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"""
<div class='threat-card' style='padding:0.75rem 1rem;margin:0.3rem 0;'>
  <span style='color:#ef4444;font-weight:700;'>{i:02d}</span>
  &nbsp;
  <span style='color:#cbd5e1;font-size:0.85rem;'>{rec}</span>
</div>
""", unsafe_allow_html=True)

    st.markdown("---")
    with st.expander("🔎 Raw Event Summary sent to AI"):
        raw = ai_result.get("raw_summary", "")
        st.code(raw, language="text")


# ── Tab 5: Report ────────────────────────────
with tab5:
    report_md = st.session_state.report_md or ""
    st.markdown("#### Incident Report Preview")
    st.markdown(report_md)

    st.download_button(
        label="⬇️ Download Report (.md)",
        data=report_md.encode("utf-8"),
        file_name="threatgraph_incident_report.md",
        mime="text/markdown",
        use_container_width=True,
    )
