"""
ThreatGraph AI Explainer
Sends attack summaries to OpenAI and returns a structured explanation.
"""

from __future__ import annotations
import os
from .correlator import AttackGraph, summarise_for_ai

SYSTEM_PROMPT = """You are an elite cybersecurity analyst specialising in incident response and threat hunting.
You will be given a chronological list of correlated security events extracted from log files.
Your task is to:

1. Explain the attack in plain English — what happened, step by step.
2. Identify the attack type (e.g. brute force + post-compromise, APT lateral movement, ransomware staging).
3. Assess the severity (Critical / High / Medium / Low) and explain why.
4. List the top 3–5 recommended response actions.

Be concise, precise, and write like a senior SOC analyst would in an incident report.
Do NOT add generic caveats. Be direct."""


def explain_attack(attack_graph: AttackGraph, api_key: str | None = None) -> dict:
    """
    Returns a dict with keys:
      - explanation: str
      - attack_type: str
      - severity: str
      - recommendations: list[str]
    """
    key = api_key or os.getenv("OPENAI_API_KEY", "")
    if not key:
        return _mock_explanation(attack_graph)

    summary = summarise_for_ai(attack_graph)

    try:
        from openai import OpenAI
        client = OpenAI(api_key=key)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyse these events and produce your report:\n\n{summary}"},
            ],
            temperature=0.3,
            max_tokens=800,
        )
        raw = response.choices[0].message.content
        return _parse_ai_response(raw, attack_graph)
    except Exception as e:
        return {
            "explanation": f"AI analysis unavailable: {e}\n\nRaw summary:\n{summary}",
            "attack_type": "Unknown",
            "severity": "Unknown",
            "recommendations": ["Review logs manually."],
            "raw_summary": summary,
        }


def _mock_explanation(attack_graph: AttackGraph) -> dict:
    """Fallback explanation when no API key is present — rule-based."""
    stages = set(n.stage for n in attack_graph.nodes)
    node_types = {n.event_type for n in attack_graph.nodes}

    attack_type = "Unknown"
    severity = "Medium"
    explanation_parts = []
    recommendations = []

    if "AUTH_FAILED" in node_types and "AUTH_SUCCESS" in node_types:
        attack_type = "Credential Brute Force + Post-Compromise"
        severity = "Critical"
        failed_count = next((n.count for n in attack_graph.nodes if n.event_type == "AUTH_FAILED"), 0)
        explanation_parts.append(
            f"An attacker from {attack_graph.attacker_ip or 'unknown IP'} conducted a credential brute force "
            f"attack with {failed_count} failed authentication attempts before successfully logging in."
        )
        recommendations.append(f"Block attacker IP {attack_graph.attacker_ip} at perimeter firewall immediately.")
        recommendations.append(f"Reset credentials for user '{attack_graph.affected_user or 'affected accounts'}'.")

    if "PORT_SCAN" in node_types:
        explanation_parts.insert(0, "The attack was preceded by a port scan, indicating the attacker mapped the target's exposed services before attempting exploitation.")
        recommendations.append("Review firewall rules and minimise exposed attack surface.")

    if "POWERSHELL_EXEC" in node_types:
        explanation_parts.append("Following initial access, the attacker executed obfuscated PowerShell commands, a common technique for payload delivery and defence evasion.")
        recommendations.append("Enable PowerShell script block logging and constrained language mode.")

    if any(t in node_types for t in ("PERSISTENCE_REGISTRY", "PERSISTENCE_STARTUP", "PERSISTENCE_SCHEDULED_TASK", "USER_CREATED")):
        explanation_parts.append("The attacker established multiple persistence mechanisms to maintain access across reboots and credential resets.")
        recommendations.append("Audit startup items, scheduled tasks, registry Run keys, and newly created user accounts.")

    if "DATA_EXFIL" in node_types:
        exfil_node = next((n for n in attack_graph.nodes if n.event_type == "DATA_EXFIL"), None)
        if exfil_node and exfil_node.raw_events:
            total_bytes = sum(e.get("bytes_sent") or 0 for e in exfil_node.raw_events)
        else:
            total_bytes = 0
        mb = total_bytes / (1024 * 1024)
        explanation_parts.append(
            f"Significant data exfiltration was detected ({mb:.1f} MB) to an external IP, "
            "indicating the attacker successfully extracted sensitive data."
        )
        severity = "Critical"
        recommendations.append("Identify and classify all data accessible by the compromised account. Notify data protection officer if PII was involved.")

    if "C2_BEACON" in node_types:
        explanation_parts.append("Command-and-control beaconing was observed on non-standard ports, suggesting the attacker maintained an interactive shell on the compromised host.")
        recommendations.append("Block C2 IPs and domains at DNS and firewall level. Forensically image the compromised host.")

    if not explanation_parts:
        explanation_parts.append("Suspicious activity detected. Review the attack graph for details.")

    if not recommendations:
        recommendations.append("Escalate to Tier 2 analyst for manual investigation.")

    recommendations.append("Conduct a full compromise assessment across adjacent systems.")

    return {
        "explanation": " ".join(explanation_parts),
        "attack_type": attack_type,
        "severity": severity,
        "recommendations": recommendations[:6],
        "raw_summary": summarise_for_ai(attack_graph),
    }


def _parse_ai_response(raw: str, attack_graph: AttackGraph) -> dict:
    """Best-effort structured parse of the AI response."""
    severity = "High"
    attack_type = "Unknown"

    for word in ["Critical", "High", "Medium", "Low"]:
        if word.lower() in raw.lower():
            severity = word
            break

    # Extract recommendations (lines starting with - or numbered)
    import re
    rec_lines = re.findall(r"(?:^|\n)\s*(?:\d+\.|[-•])\s*(.+)", raw)
    recommendations = [r.strip() for r in rec_lines if len(r.strip()) > 10][:6]

    if not recommendations:
        recommendations = ["Review the attack graph and take remediation steps."]

    return {
        "explanation": raw,
        "attack_type": attack_type,
        "severity": severity,
        "recommendations": recommendations,
        "raw_summary": summarise_for_ai(attack_graph),
    }
