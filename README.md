# ThreatGraph

> **Upload logs. Reconstruct attacks. Visualise the kill chain.**

ThreatGraph automatically detects, correlates, and explains attacks from raw security logs — turning hours of manual SOC work into a seconds-long automated investigation.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-red?logo=streamlit)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange)

---

<!-- After running the app, take a screenshot of the attack graph tab and save it as
     docs/screenshot.png, then uncomment the line below to show it in the README -->
<!-- ![ThreatGraph Screenshot](docs/screenshot.png) -->

---

## The Problem

SOC analysts spend **30–60 minutes** reconstructing a single attack chain by hand — pivoting between log sources, correlating timestamps, and building a mental picture of what happened.

ThreatGraph does it in **seconds**.

---

## What It Does

Upload `sysmon.log`, `auth.log`, and `network.log`. Get back:

```
Attack Chain Detected  ·  CRITICAL

1.  [Reconnaissance]       Port scan from 185.220.101.45  ·  T1046
2.  [Initial Access]       22 failed SSH logins (root, admin, ubuntu)  ·  T1110
3.  [Initial Access]       Successful login: ubuntu from 185.220.101.45  ·  T1078
4.  [Execution]            Root shell via sudo  ·  T1548.003
5.  [Execution]            Encoded PowerShell execution  ·  T1059.001
6.  [Persistence]          New account created: support  ·  T1136
7.  [Privilege Escalation] Privilege escalation (admin group)  ·  T1548
8.  [Persistence]          Registry run key added  ·  T1547.001
9.  [Command & Control]    C2 beacon → 185.220.101.45:4444  ·  T1071
10. [Exfiltration]         Data exfiltration → 185.220.101.45 (112.8 MB)  ·  T1041
```

Visualised as an interactive attack graph with MITRE ATT&CK mappings and a downloadable incident report.

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-source log parsing** | Sysmon, auth.log, network/firewall logs |
| **Automatic event correlation** | 10,000 alerts → 10 meaningful chain nodes |
| **Attack graph visualisation** | Interactive Plotly graph, colour-coded by kill chain stage |
| **MITRE ATT&CK mapping** | Auto-mapped techniques with links to ATT&CK matrix |
| **AI threat explanation** | GPT-4o-mini powered narrative (rule-based fallback if no key) |
| **Incident report generator** | Full markdown report ready to download or paste into a ticket |
| **CLI interface** | Scriptable, CI/CD friendly |

---

## Prerequisites

Before you start, make sure you have:

- **Python 3.10 or higher** — download from [python.org](https://www.python.org/downloads/)
  - **Windows users:** During installation, check the box that says **"Add Python to PATH"** — it is unchecked by default and things will not work without it
- **Git** — download from [git-scm.com](https://git-scm.com/downloads)

To verify your installs, open a terminal and run:
```bash
python --version    # should say Python 3.10 or higher
git --version       # should say git version x.x.x
```

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/Pukarkafley21/ThreatGraph.git
cd ThreatGraph

# 2. Install dependencies (takes 1-2 minutes)
pip install -r requirements.txt

# 3. Run the app
python -m streamlit run app.py
```

Your browser will open automatically at http://localhost:8501. Click **Load Sample Logs** in the sidebar to see a full attack investigation demo instantly.

> **Note:** Use `python -m streamlit run app.py` rather than just `streamlit run app.py`. On Windows the shorter version often fails with a "not recognized" error — the longer version works on all platforms.

---

## Using Your Own Logs

1. Run the app with `python -m streamlit run app.py`
2. In the sidebar, click **Browse files** and upload any combination of:
   - `sysmon.log` — Windows Sysmon process and network events
   - `auth.log` — Linux SSH / PAM authentication logs
   - `network.log` — iptables or firewall logs
3. Optionally paste an OpenAI API key in the sidebar for GPT-powered analysis
4. Click **Analyse Logs**

You can upload just one file or all three — the more sources you provide, the more complete the attack chain.

---

## OpenAI API Key (Optional)

ThreatGraph works **without an API key** — it uses a built-in rule-based engine to generate the threat explanation and recommendations.

If you add an OpenAI API key, it upgrades the analysis to GPT-4o-mini for a richer narrative. You can either paste it into the sidebar when running the app, or create a `.env` file:

**Windows (PowerShell):**
```powershell
copy .env.example .env
notepad .env
```

**Mac / Linux:**
```bash
cp .env.example .env
nano .env
```

The `.env` file should look like this:
```
OPENAI_API_KEY=sk-your-key-here
```

---

## CLI Usage

You can also run ThreatGraph from the command line without the web UI:

```bash
# Run against the built-in sample logs
python -m threatgraph.cli --sample

# Run against your own log files
python -m threatgraph.cli --logs sysmon.log auth.log network.log --output report.md

# With an OpenAI key for GPT analysis
python -m threatgraph.cli --logs sysmon.log auth.log network.log --key sk-your-key --output report.md
```

---

## Supported Log Formats

### auth.log (Linux PAM / sshd)
```
Jan 15 11:58:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 52341 ssh2
Jan 15 11:58:31 server sshd[1235]: Accepted password for john from 1.2.3.4 port 52360 ssh2
Jan 15 12:00:00 server useradd[2100]: new user: name=backdoor, UID=1337
Jan 15 11:59:00 server sudo[2001]: john : USER=root ; COMMAND=/bin/bash
```

### sysmon.log (Windows Sysmon)
```
2024-01-20 12:00:45 EventID=1 ProcessCreate Image=C:\...\powershell.exe CommandLine="..." User=john
2024-01-20 12:01:02 EventID=3 NetworkConnect SourceIp=192.168.1.50 DestinationIp=1.2.3.4 DestinationPort=443
2024-01-20 12:02:00 EventID=11 FileCreate TargetFilename=C:\...\Startup\update.bat
```

### network.log (iptables / firewall)
```
2024-01-20 11:55:00 SRC=1.2.3.4 DST=192.168.1.50 PROTO=TCP DPT=22 FLAGS=SYN LEN=60
2024-01-20 12:03:45 SRC=192.168.1.50 DST=1.2.3.4 PROTO=TCP DPT=443 FLAGS=ACK BYTES=45234567
```

---

## Architecture

```
logs (sysmon / auth / network)
         |
         v
    parser.py          <- normalises every log format into a unified event schema
         |
         v
   correlator.py       <- groups events, builds AttackGraph, assigns kill chain stages
         |
         v
  graph_builder.py     <- NetworkX layout -> Plotly interactive figure
         |
         v
   ai_explainer.py     <- GPT-4o-mini narrative (rule-based fallback if no API key)
         |
         v
report_generator.py    <- downloadable markdown incident report
         |
         v
      app.py           <- Streamlit dashboard tying it all together
```

---

## MITRE ATT&CK Coverage

| Technique | Name | Detected Via |
|-----------|------|-------------|
| T1046 | Network Service Discovery | Port scan (8+ SYN packets from same IP) |
| T1110 | Brute Force | AUTH_FAILED flood |
| T1078 | Valid Accounts | Successful login following brute force |
| T1548 | Abuse Elevation Control | usermod + sudo to root |
| T1059.001 | PowerShell | Sysmon EventID=1, encoded command |
| T1136 | Create Account | useradd / net user /add |
| T1547.001 | Registry Run Keys | reg add CurrentVersion\Run |
| T1053.005 | Scheduled Task | schtasks /create |
| T1071 | Application Layer Protocol | Outbound C2 traffic |
| T1041 | Exfiltration Over C2 | Large outbound transfer (>1 MB) |

---

## Troubleshooting

**`streamlit` is not recognized**
```bash
python -m streamlit run app.py
```

**`pip` is not recognized**
```bash
python -m pip install -r requirements.txt
```

**`python` is not recognized on Windows**
Reinstall Python from python.org and tick "Add to PATH", or try:
```bash
py -m streamlit run app.py
```

**Browser does not open automatically**
Go to http://localhost:8501 manually in your browser.

**Port 8501 already in use**
```bash
python -m streamlit run app.py --server.port 8502
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Roadmap

- [ ] Add screenshots to README
- [ ] Sigma rule integration
- [ ] Windows Event Log (.evtx) support
- [ ] STIX/TAXII threat intel feed integration
- [ ] Multi-host lateral movement detection
- [ ] Elastic / Splunk log ingest connectors
- [ ] Real-time log streaming (Kafka/Filebeat)
- [ ] PDF report export

---

## Contributing

Pull requests welcome. Please open an issue first for large changes.

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push and open a PR

---



---

*Built because SOC analysts deserve better tools.*
