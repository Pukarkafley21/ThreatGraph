"""ThreatGraph — Autonomous Threat Investigation Engine"""
from .parser import parse_logs
from .correlator import correlate, AttackGraph
from .report_generator import generate_report

def build_graph_figure(attack_graph):
    from .graph_builder import build_graph_figure as _build
    return _build(attack_graph)

def explain_attack(attack_graph, api_key=None):
    from .ai_explainer import explain_attack as _explain
    return _explain(attack_graph, api_key=api_key)
