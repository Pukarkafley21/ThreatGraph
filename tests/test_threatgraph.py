"""
ThreatGraph Tests
Run with: pytest tests/
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from threatgraph.parser import parse_auth_log, parse_sysmon_log, parse_network_log, parse_logs
from threatgraph.correlator import correlate


# ──────────────────────────────────────────────
# Parser tests
# ──────────────────────────────────────────────

AUTH_SAMPLE = """Jan 15 11:58:01 server sshd[1234]: Failed password for root from 194.88.21.10 port 52341 ssh2
Jan 15 11:58:31 server sshd[1235]: Accepted password for john from 194.88.21.10 port 52360 ssh2
Jan 15 12:00:00 server useradd[2100]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor
Jan 15 12:00:05 server usermod[2101]: add 'backdoor' to group 'sudo'
Jan 15 11:59:00 server sudo[2001]: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash"""

SYSMON_SAMPLE = """2024-01-15 12:00:45 EventID=1 ProcessCreate Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="powershell.exe -nop -w hidden -enc JABj" User=WORKSTATION\\john ParentImage=C:\\Windows\\System32\\cmd.exe
2024-01-15 12:01:02 EventID=3 NetworkConnect SourceIp=192.168.1.50 DestinationIp=194.88.21.10 DestinationPort=443 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
2024-01-15 12:03:45 EventID=3 NetworkConnect SourceIp=192.168.1.50 DestinationIp=194.88.21.10 DestinationPort=443 BytesSent=45234567 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"""

NETWORK_SAMPLE = """2024-01-15 11:55:00 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=22 SPT=52000 FLAGS=SYN LEN=60
2024-01-15 11:55:01 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=80 SPT=52001 FLAGS=SYN LEN=60
2024-01-15 11:55:02 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=443 SPT=52002 FLAGS=SYN LEN=60
2024-01-15 11:55:03 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=3389 SPT=52003 FLAGS=SYN LEN=60
2024-01-15 11:55:04 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=8080 SPT=52004 FLAGS=SYN LEN=60
2024-01-15 11:55:05 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=21 SPT=52005 FLAGS=SYN LEN=60
2024-01-15 11:55:06 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=23 SPT=52006 FLAGS=SYN LEN=60
2024-01-15 11:55:07 SRC=194.88.21.10 DST=192.168.1.50 PROTO=TCP DPT=25 SPT=52007 FLAGS=SYN LEN=60
2024-01-15 12:02:31 SRC=192.168.1.50 DST=194.88.21.10 PROTO=TCP DPT=4444 SPT=49200 FLAGS=ACK LEN=500 BYTES=51200"""


class TestAuthParser:
    def test_parses_failed_logins(self):
        events = parse_auth_log(AUTH_SAMPLE)
        failed = [e for e in events if e["event_type"] == "AUTH_FAILED"]
        assert len(failed) == 1
        assert failed[0]["src_ip"] == "194.88.21.10"
        assert failed[0]["user"] == "root"

    def test_parses_successful_login(self):
        events = parse_auth_log(AUTH_SAMPLE)
        success = [e for e in events if e["event_type"] == "AUTH_SUCCESS"]
        assert len(success) == 1
        assert success[0]["user"] == "john"

    def test_parses_user_created(self):
        events = parse_auth_log(AUTH_SAMPLE)
        created = [e for e in events if e["event_type"] == "USER_CREATED"]
        assert len(created) == 1
        assert created[0]["user"] == "backdoor"

    def test_parses_privilege_escalation(self):
        events = parse_auth_log(AUTH_SAMPLE)
        priv = [e for e in events if e["event_type"] == "PRIVILEGE_ESCALATION"]
        assert len(priv) == 1

    def test_parses_sudo(self):
        events = parse_auth_log(AUTH_SAMPLE)
        sudo = [e for e in events if e["event_type"] == "SUDO_EXEC"]
        assert len(sudo) == 1


class TestSysmonParser:
    def test_parses_powershell(self):
        events = parse_sysmon_log(SYSMON_SAMPLE)
        ps = [e for e in events if e["event_type"] == "POWERSHELL_EXEC"]
        assert len(ps) == 1

    def test_parses_network_connect(self):
        events = parse_sysmon_log(SYSMON_SAMPLE)
        net = [e for e in events if e["event_type"] == "NETWORK_CONNECT"]
        assert len(net) == 1
        assert net[0]["dst_ip"] == "194.88.21.10"

    def test_parses_data_exfil(self):
        events = parse_sysmon_log(SYSMON_SAMPLE)
        exfil = [e for e in events if e["event_type"] == "DATA_EXFIL"]
        assert len(exfil) == 1
        assert exfil[0]["bytes_sent"] == 45234567


class TestNetworkParser:
    def test_detects_port_scan(self):
        events = parse_network_log(NETWORK_SAMPLE)
        scans = [e for e in events if e["event_type"] == "PORT_SCAN"]
        assert len(scans) >= 1
        assert scans[0]["src_ip"] == "194.88.21.10"

    def test_detects_c2_beacon(self):
        events = parse_network_log(NETWORK_SAMPLE)
        c2 = [e for e in events if e["event_type"] == "C2_BEACON"]
        assert len(c2) >= 1
        assert c2[0]["port"] == 4444


class TestCorrelator:
    def setup_method(self):
        files = {
            "auth.log": AUTH_SAMPLE,
            "sysmon.log": SYSMON_SAMPLE,
            "network.log": NETWORK_SAMPLE,
        }
        df = parse_logs(files)
        self.graph = correlate(df)

    def test_attack_graph_has_nodes(self):
        assert len(self.graph.nodes) > 0

    def test_detects_attacker_ip(self):
        assert self.graph.attacker_ip == "194.88.21.10"

    def test_detects_affected_user(self):
        assert self.graph.affected_user == "john"

    def test_nodes_are_sorted_by_time(self):
        timestamps = [n.timestamp for n in self.graph.nodes]
        assert timestamps == sorted(timestamps)

    def test_edges_connect_sequential_nodes(self):
        node_ids = [n.node_id for n in self.graph.nodes]
        for src, dst in self.graph.edges:
            src_idx = node_ids.index(src)
            dst_idx = node_ids.index(dst)
            assert dst_idx == src_idx + 1

    def test_all_nodes_have_mitre(self):
        for node in self.graph.nodes:
            # Not every event type needs a MITRE mapping, but key ones should
            if node.event_type in ("AUTH_FAILED", "AUTH_SUCCESS", "POWERSHELL_EXEC", "DATA_EXFIL"):
                assert len(node.mitre) > 0, f"Missing MITRE for {node.event_type}"

    def test_stages_observed(self):
        assert len(self.graph.stages_observed) > 0
        assert "Initial Access" in self.graph.stages_observed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
