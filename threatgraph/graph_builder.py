"""
ThreatGraph Graph Builder
Converts an AttackGraph into a Plotly figure using NetworkX for layout.
"""

from __future__ import annotations
import networkx as nx
import plotly.graph_objects as go
from .correlator import AttackGraph, STAGE_ORDER

# Stage → colour palette (dark terminal aesthetic)
STAGE_COLORS: dict[str, str] = {
    "Reconnaissance":      "#f59e0b",   # amber
    "Initial Access":      "#ef4444",   # red
    "Execution":           "#f97316",   # orange
    "Privilege Escalation":"#a855f7",   # purple
    "Persistence":         "#8b5cf6",   # violet
    "Defense Evasion":     "#6366f1",   # indigo
    "Command & Control":   "#0ea5e9",   # sky blue
    "Exfiltration":        "#10b981",   # emerald
    "Unknown":             "#6b7280",   # gray
}

NODE_SIZE_BASE = 28
NODE_SIZE_SCALE = 4


def build_graph_figure(attack_graph: AttackGraph) -> go.Figure:
    """
    Build a Plotly figure from an AttackGraph.
    Uses a top-down hierarchical layout.
    """
    if not attack_graph.nodes:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font_color="#94a3b8",
            annotations=[{
                "text": "No events detected — upload logs to begin",
                "xref": "paper", "yref": "paper",
                "x": 0.5, "y": 0.5,
                "showarrow": False,
                "font": {"size": 18, "color": "#475569"},
            }],
        )
        return fig

    G = nx.DiGraph()
    for node in attack_graph.nodes:
        G.add_node(node.node_id, **node.to_dict())
    for src, dst in attack_graph.edges:
        G.add_edge(src, dst)

    # Simple vertical layout based on stage order
    pos: dict[str, tuple[float, float]] = {}
    stage_indices = {stage: i for i, stage in enumerate(STAGE_ORDER)}

    # Group nodes by stage
    stage_groups: dict[str, list] = {}
    for node in attack_graph.nodes:
        stage_groups.setdefault(node.stage, []).append(node)

    for node in attack_graph.nodes:
        y = -stage_indices.get(node.stage, 0)
        siblings = stage_groups.get(node.stage, [node])
        x_offset = (siblings.index(node) - (len(siblings) - 1) / 2) * 2.5
        pos[node.node_id] = (x_offset, y)

    # ── Edge traces ──────────────────────────────────────────────
    edge_x, edge_y = [], []
    for src_id, dst_id in attack_graph.edges:
        x0, y0 = pos[src_id]
        x1, y1 = pos[dst_id]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line={"width": 2, "color": "#334155"},
        hoverinfo="none",
        showlegend=False,
    )

    # ── Node traces (one per stage for legend) ───────────────────
    stage_traces: dict[str, go.Scatter] = {}
    for node in attack_graph.nodes:
        color = STAGE_COLORS.get(node.stage, "#6b7280")
        size = NODE_SIZE_BASE + min(node.count, 20) * NODE_SIZE_SCALE

        hover_lines = [
            f"<b>{node.label}</b>",
            f"Stage: {node.stage}",
            f"Time: {str(node.timestamp)[:19]}",
        ]
        if node.src_ip:
            hover_lines.append(f"Source: {node.src_ip}")
        if node.dst_ip:
            hover_lines.append(f"Destination: {node.dst_ip}")
        if node.user:
            hover_lines.append(f"User: {node.user}")
        if node.count > 1:
            hover_lines.append(f"Events: {node.count}")
        if node.mitre:
            techs = ", ".join(t[0] for t in node.mitre)
            hover_lines.append(f"MITRE: {techs}")

        x, y = pos[node.node_id]
        if node.stage not in stage_traces:
            stage_traces[node.stage] = go.Scatter(
                x=[], y=[],
                mode="markers+text",
                name=node.stage,
                marker={
                    "size": [],
                    "color": color,
                    "line": {"width": 2, "color": "#1e293b"},
                    "symbol": "circle",
                },
                text=[],
                textposition="middle right",
                textfont={"color": "#e2e8f0", "size": 11},
                hovertext=[],
                hoverinfo="text",
                showlegend=True,
            )

        t = stage_traces[node.stage]
        t.x = list(t.x) + [x]
        t.y = list(t.y) + [y]
        t.marker.size = list(t.marker.size) + [size]
        t.text = list(t.text) + [_truncate(node.label, 40)]
        t.hovertext = list(t.hovertext) + ["<br>".join(hover_lines)]

    # ── Arrow annotations ────────────────────────────────────────
    arrows = []
    for src_id, dst_id in attack_graph.edges:
        x0, y0 = pos[src_id]
        x1, y1 = pos[dst_id]
        arrows.append({
            "x": x1, "y": y1,
            "ax": x0, "ay": y0,
            "xref": "x", "yref": "y",
            "axref": "x", "ayref": "y",
            "showarrow": True,
            "arrowhead": 2,
            "arrowsize": 1.5,
            "arrowwidth": 1.5,
            "arrowcolor": "#475569",
        })

    # ── Layout ───────────────────────────────────────────────────
    all_x = [p[0] for p in pos.values()]
    all_y = [p[1] for p in pos.values()]
    x_pad, y_pad = 2.5, 0.8

    fig = go.Figure(
        data=[edge_trace] + list(stage_traces.values()),
        layout=go.Layout(
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font={"color": "#94a3b8", "family": "JetBrains Mono, monospace"},
            showlegend=True,
            legend={
                "bgcolor": "#1e293b",
                "bordercolor": "#334155",
                "borderwidth": 1,
                "font": {"color": "#cbd5e1", "size": 11},
                "title": {"text": "Kill Chain Stage", "font": {"color": "#94a3b8"}},
            },
            xaxis={
                "showgrid": False, "zeroline": False, "showticklabels": False,
                "range": [min(all_x) - x_pad, max(all_x) + x_pad + 4],
            },
            yaxis={
                "showgrid": False, "zeroline": False, "showticklabels": False,
                "range": [min(all_y) - y_pad, max(all_y) + y_pad],
            },
            annotations=arrows,
            margin={"l": 20, "r": 20, "t": 20, "b": 20},
            height=600,
            hovermode="closest",
        ),
    )
    return fig


def _truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"
