"""
ThreatGraph CLI
Usage: threatgraph --logs sysmon.log auth.log network.log [--key sk-...]
"""

import argparse
import sys
import os
from .parser import parse_logs
from .correlator import correlate
from .ai_explainer import explain_attack
from .report_generator import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog="threatgraph",
        description="ThreatGraph — Autonomous Threat Investigation Engine",
    )
    parser.add_argument(
        "--logs", nargs="+", metavar="FILE",
        help="Log files to analyse (sysmon.log, auth.log, network.log)",
    )
    parser.add_argument(
        "--key", metavar="OPENAI_KEY",
        default=os.getenv("OPENAI_API_KEY"),
        help="OpenAI API key (or set OPENAI_API_KEY env var)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        default="report.md",
        help="Output report filename (default: report.md)",
    )
    parser.add_argument(
        "--sample", action="store_true",
        help="Run against the bundled sample logs",
    )
    args = parser.parse_args()

    files: dict[str, str] = {}

    if args.sample:
        sample_dir = os.path.join(os.path.dirname(__file__), "..", "sample_logs")
        for fname in ("sysmon.log", "auth.log", "network.log"):
            path = os.path.join(sample_dir, fname)
            if os.path.exists(path):
                with open(path) as f:
                    files[fname] = f.read()
        if not files:
            print("[!] Sample logs not found.", file=sys.stderr)
            sys.exit(1)
    elif args.logs:
        for filepath in args.logs:
            with open(filepath, "r", errors="replace") as f:
                files[os.path.basename(filepath)] = f.read()
    else:
        parser.print_help()
        sys.exit(0)

    print("[*] Parsing logs…")
    df = parse_logs(files)
    if df.empty:
        print("[!] No events parsed. Check log formats.")
        sys.exit(1)
    print(f"    {len(df)} raw events parsed.")

    print("[*] Correlating events…")
    graph = correlate(df)
    print(f"    {len(graph.nodes)} attack chain nodes built.")

    print("[*] Running AI analysis…")
    ai_result = explain_attack(graph, api_key=args.key)

    print("[*] Generating report…")
    report = generate_report(graph, ai_result, filename=args.output)
    print(f"    Report saved to: {args.output}")

    # Print summary to stdout
    print("\n" + "═" * 60)
    print("ATTACK CHAIN DETECTED")
    print("═" * 60)
    for i, node in enumerate(graph.nodes, 1):
        mitre = " | ".join(t[0] for t in node.mitre)
        print(f"{i:2}. [{node.stage:22s}] {node.label}")
        if mitre:
            print(f"    MITRE: {mitre}")
    print("═" * 60)
    print(f"Severity : {ai_result.get('severity', '?')}")
    print(f"Attacker : {graph.attacker_ip or 'Unknown'}")
    print(f"User     : {graph.affected_user or 'Unknown'}")
    print("═" * 60)


if __name__ == "__main__":
    main()
