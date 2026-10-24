"""
Pytest fixtures for Suricata rule testing.
Provides the SuricataTestRunner and shared test infrastructure.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

RULES_FILE = str(Path(__file__).parent.parent / "suricata" / "iranian-apt-detection.rules")
SURICATA_BIN = shutil.which("suricata") or "/usr/bin/suricata"
SURICATA_CONFIG = "/etc/suricata/suricata.yaml"

# Default IPs matching suricata.yaml HOME_NET / EXTERNAL_NET
HOME_NET_IP = "10.0.0.1"
EXTERNAL_NET_IP = "203.0.113.1"


class SuricataTestRunner:
    """Handles pcap generation, Suricata execution, and alert parsing."""

    def __init__(self, rules_file: str = RULES_FILE):
        self.rules_file = rules_file
        self.suricata_bin = SURICATA_BIN
        self.suricata_config = SURICATA_CONFIG

    def run_suricata(self, pcap_path: str, log_dir: str, extra_args: list | None = None) -> dict:
        """Run Suricata against a pcap file and return results."""
        cmd = [
            self.suricata_bin,
            "-r", pcap_path,
            "-S", self.rules_file,
            "-l", log_dir,
            "-c", self.suricata_config,
            "--set", f"vars.address-groups.HOME_NET=[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
            "--set", "outputs.1.eve-log.enabled=yes",
        ]
        if extra_args:
            cmd.extend(extra_args)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def get_alerts(self, log_dir: str) -> list[dict]:
        """Parse eve.json for alert events."""
        eve_path = os.path.join(log_dir, "eve.json")
        alerts = []
        if not os.path.exists(eve_path):
            return alerts
        with open(eve_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue
        return alerts

    def get_fired_sids(self, log_dir: str) -> set[int]:
        """Return set of SIDs that fired."""
        alerts = self.get_alerts(log_dir)
        sids = set()
        for alert in alerts:
            sig = alert.get("alert", {})
            sid = sig.get("signature_id")
            if sid:
                sids.add(int(sid))
        return sids

    def test_pcap(self, pcap_path: str, expected_sids: set[int] | None = None) -> dict:
        """Run Suricata on a pcap and check if expected SIDs fired."""
        with tempfile.TemporaryDirectory(prefix="suricata_test_") as log_dir:
            run_result = self.run_suricata(pcap_path, log_dir)
            fired_sids = self.get_fired_sids(log_dir)
            alerts = self.get_alerts(log_dir)

            result = {
                "returncode": run_result["returncode"],
                "fired_sids": fired_sids,
                "alerts": alerts,
                "stderr": run_result["stderr"],
            }

            if expected_sids is not None:
                result["missing_sids"] = expected_sids - fired_sids
                result["unexpected_sids"] = fired_sids - expected_sids
                result["passed"] = expected_sids.issubset(fired_sids)

            return result


@pytest.fixture(scope="session")
def runner():
    """Session-scoped Suricata test runner."""
    return SuricataTestRunner()


@pytest.fixture
def tmp_pcap_dir():
    """Temporary directory for pcap files, cleaned up after test."""
    with tempfile.TemporaryDirectory(prefix="pcap_") as d:
        yield d
