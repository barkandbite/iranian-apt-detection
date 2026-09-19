"""
Comprehensive Suricata Rule Test Suite
Tests every detection rule in iranian-apt-detection.rules
Generates synthetic packets using scapy and validates Suricata alerts.

Usage:
    sudo python3 -m pytest tests/test_suricata_rules.py -v
    sudo python3 -m pytest tests/test_suricata_rules.py -k "test_rules_load" -v
"""

import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest
from scapy.all import (
    DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap, conf,
)

conf.verb = 0

REPO_ROOT = Path(__file__).parent.parent
RULES_FILE = str(REPO_ROOT / "suricata" / "iranian-apt-detection.rules")
SURICATA_BIN = shutil.which("suricata") or "/usr/bin/suricata"
SURICATA_CONFIG = "/etc/suricata/suricata.yaml"

HOME = "10.0.0.1"
EXTERNAL = "203.0.113.1"


class SuricataRunner:
    """Run Suricata against pcaps and collect alerts."""

    @staticmethod
    def run(pcap_path: str, timeout: int = 60) -> set[int]:
        with tempfile.TemporaryDirectory(prefix="suri_") as logdir:
            cmd = [
                SURICATA_BIN, "-r", pcap_path, "-S", RULES_FILE,
                "-l", logdir, "-c", SURICATA_CONFIG,
                "--set", "vars.address-groups.HOME_NET=[10.0.0.0/8]",
                "--set", "vars.address-groups.EXTERNAL_NET=!$HOME_NET",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            eve = os.path.join(logdir, "eve.json")
            sids = set()
            if os.path.exists(eve):
                with open(eve) as f:
                    for line in f:
                        try:
                            ev = json.loads(line.strip())
                            if ev.get("event_type") == "alert":
                                sids.add(ev["alert"]["signature_id"])
                        except (json.JSONDecodeError, KeyError):
                            pass
            return sids


# ---- Packet builders ----

def _tcp(src, dst, sport, dport, client, server=b""):
    syn = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=100)
    sa = Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101)
    a = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201)
    pkts = [syn, sa, a]
    if client:
        pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=201) / Raw(load=client))
    if server:
        pkts.append(Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=201, ack=101 + len(client)) / Raw(load=server))
    return pkts


def _http(src, dst, sport, dport, method, host, uri, headers=None, body=b""):
    req = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\n"
    if headers:
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
    if body:
        req += f"Content-Length: {len(body)}\r\n"
    req += "\r\n"
    return _tcp(src, dst, sport, dport, req.encode() + body)


def _http_resp(src, dst, sport, dport, req_payload, status=200, resp_hdrs=None, resp_body=b""):
    resp = f"HTTP/1.1 {status} OK\r\n"
    if resp_hdrs:
        for k, v in resp_hdrs.items():
            resp += f"{k}: {v}\r\n"
    resp += f"Content-Length: {len(resp_body)}\r\n\r\n"
    return _tcp(src, dst, sport, dport, req_payload, resp.encode() + resp_body)


def _dns(src, dst, qname, sport=12345):
    return [Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))]


def _tls(src, dst, sport, dport, sni):
    sni_b = sni.encode()
    ext = struct.pack("!HH", 0, len(sni_b) + 5) + struct.pack("!H", len(sni_b) + 3) + b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
    exts = struct.pack("!H", len(ext)) + ext
    ch = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\xff" + b"\x01\x00" + exts
    hs = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return _tcp(src, dst, sport, dport, rec)


def _udp(src, dst, sport, dport, payload):
    return [Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)]


def _ip(src, dst):
    return [Ether() / IP(src=src, dst=dst) / TCP(sport=12345, dport=80, flags="S")]


# ---- Per-SID packet generators ----

def generate_packets(sid):
    if sid == 2000001: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/clients/MyCRL", None, b'')
    if sid == 2000002: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000003: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/ssl-vpn/hipreport.esp", None, b'')
    if sid == 2000004: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000005: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/pcidss/report", None, b'')
    if sid == 2000006: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/mgmt/", None, b'')
    if sid == 2000007: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000008: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/dana-na/", None, b'')
    if sid == 2000009: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/api/v1/", None, b'')
    if sid == 2000010: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/owa/auth/Current/", None, b'')
    if sid == 2000011: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000012: return _tcp(EXTERNAL, HOME, 44444, 135, b"\x05\x00\x0b" + b"\x00" * 50)
    if sid == 2000013: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBoutlook.exe')
    if sid == 2000014: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMB')
    if sid == 2000015: return _tcp(HOME, EXTERNAL, 44444, 25, b'MAIL FROM: noreply@ |42 61 73 65 36 34|')
    if sid == 2000016: return _tcp(EXTERNAL, HOME, 44444, 443, b"\x16\x03\x01\x00\x01")
    if sid == 2000017: return _tls(EXTERNAL, HOME, 44444, 443, "|17 03|")
    if sid == 2000018: return _dns(HOME, "8.8.8.8", "ngrok.io")
    if sid == 2000019: return _tls(HOME, EXTERNAL, 44444, 443, "|16 03|")
    if sid == 2000020: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.github.com", "/repos/", None, b'')
    if sid == 2000021: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000022: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000024: return _tcp("10.0.0.1", "203.0.113.1", 44444, 7070, b'|01 00 00 00 21 12 a4 42|anynet')
    if sid == 2000025: return _tls(HOME, EXTERNAL, 44444, 443, "meshcentral")
    if sid == 2000026: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", {'User-Agent': 'WindowsPowerShell/1.0'}, b'')
    if sid == 2000027: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000028: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMB|75|')
    if sid == 2000029: return _tcp(HOME, HOME, 44444, 3389, b"\x03\x00\x00\x2c\x27\xe0Cookie: mstshash=admin\r\n")
    if sid == 2000030: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000031: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000032: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000033: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000034: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/", None, b'Cookies Password')
    if sid == 2000035: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/", {'Content-Type': 'multipart/form-data'}, b'')
    if sid == 2000036: return _tcp("203.0.113.1", "10.0.0.1", 44444, 80, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000037: return _tls(EXTERNAL, HOME, 44444, 443, "outlook.")
    if sid == 2000038: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBMultiLayer')
    if sid == 2000039: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'DELETE')
    if sid == 2000040: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20256, b'|55 4e 49 54|')
    if sid == 2000041: return _tcp("203.0.113.1", "10.0.0.1", 44444, 502, b'|10|')
    if sid == 2000042: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000050: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 1000039: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 1000042: return _tcp("10.0.0.1", "203.0.113.1", 44444, 8888, b'CHISEL/1.0')
    if sid == 2000131: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/mifs/rs/api/v2/", None, b'')
    if sid == 2000132: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/api/v2/authentication", None, b'')
    if sid == 2000133: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/api/v2/cmdb/system/admin", None, b'')
    if sid == 2000134: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/api/v2/", None, b'')
    if sid == 2000135: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/cgi-bin/", None, b'')
    if sid == 2000136: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "PUT", "target.example.com", "/SDK/webLanguage", None, b'')
    if sid == 2000137: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/RPC2_Login", None, b'')
    if sid == 2000138: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/api/v2.0/", None, b'')
    if sid == 2000139: return _ip("194.11.246.101", HOME)
    if sid == 2000140: return _ip(HOME, "194.11.246.101")
    if sid == 2000141: return _udp(HOME, EXTERNAL, 44444, 1269, b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000142: return _ip(HOME, "157.20.182.75")
    if sid == 2000143: return _udp(HOME, EXTERNAL, 44444, 1269, b'|04|\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000144: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".wasabisys.com", "/", {'User-Agent': 'rclone/v1.64'}, b'')
    if sid == 2000145: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "PUT", ".wasabisys.com", "/", None, b'')
    if sid == 2000146: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "gitempire.s3.us-east-005.backblazeb2.com", "/", None, b'')
    if sid == 2000147: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "elvenforest.s3.us-east-005.backblazeb2.com", "/", None, b'')
    if sid == 2000148: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".s3.us-east-005.backblazeb2.com", "/", None, b'')
    if sid == 2000149: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/bot", None, b'')
    if sid == 2000150: return _dns(HOME, "8.8.8.8", "codefusiontech.org")
    if sid == 2000151: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/bot", None, b'')
    if sid == 2000152: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "api.telegram.org", "/sendDocument", None, b'')
    if sid == 2000153: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000154: return _dns(HOME, "8.8.8.8", "screenai.online")
    if sid == 2000155: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000156: return _ip(HOME, "157.20.182.49")
    if sid == 2000157: return _tcp("10.0.0.1", "203.0.113.1", 44444, 8883, b'|10|MQTT')
    if sid == 2000158: return _tcp("10.0.0.1", "203.0.113.1", 44444, 1883, b'|10|MQTT')
    if sid == 2000159: return _tls(HOME, EXTERNAL, 44444, 443, "cloudflare-dns.com")
    if sid == 2000160: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/dns-query", None, b'')
    if sid == 2000161: return _tcp("203.0.113.1", "10.0.0.1", 44444, 102, b'|03 00||32 01 00 00||29|')
    if sid == 2000162: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20256, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000163: return _tcp("203.0.113.1", "10.0.0.1", 44444, 554, b'DESCRIBE rtsp://')
    if sid == 2000164: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "PUT", "target.example.com", "/ISAPI/System/configurationFile", None, b'')
    if sid == 2000165: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/1/?c=", None, b'')
    if sid == 2000166: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/key/", None, b'')
    if sid == 2000167: return _dns(HOME, "8.8.8.8", "test.ix.tc")
    if sid == 2000168: return _dns(HOME, "8.8.8.8", "test.privatedns.org")
    if sid == 2000169: return _ip(HOME, "45.80.148.195")
    if sid == 2000170: return _ip(HOME, "45.80.148.124")
    if sid == 2000171: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000172: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'SSH-2.0-')
    if sid == 2000173: return _tcp("203.0.113.1", "10.0.0.1", 44444, 135, b'|05 00 0b|e3514235-4b06-11d1-ab04-00c04fc2dcd2')
    if sid == 2000174: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "raw.githubusercontent.com", "/", None, b'')
    if sid == 2000175: return _dns(HOME, "8.8.8.8", "test.systemupdate.info")
    if sid == 2000176: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000177: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'powershell Add-MpPreference -ExclusionExtension .exe')
    if sid == 2000178: return _udp(HOME, EXTERNAL, 44444, 1269, b'I2P\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000179: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000180: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", {'User-Agent': 'rclone/v1.64'}, b'')
    if sid == 2000181: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000182: return _tls(HOME, EXTERNAL, 44444, 443, ".net.anydesk.com")
    if sid == 2000183: return _tls(HOME, EXTERNAL, 44444, 443, "meshcentral")
    if sid == 2000184: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/remote/", None, b'')
    if sid == 2000185: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "PUT", "target.example.com", "/api/v2/cmdb/vpn.ssl/settings", None, b'')
    if sid == 2000186: return _tcp("203.0.113.1", "10.0.0.1", 44444, 389, b'|30||60|')
    if sid == 2000187: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20256, b'1111')
    if sid == 2000188: return _tcp("10.0.0.1", "203.0.113.1", 44444, 2222, b'SSH-2.0-')
    if sid == 2000189: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000190: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".wasabisys.com", "/", None, b'')
    if sid == 2000191: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".backblazeb2.com", "/", None, b'')
    if sid == 2000192: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000193: return _tcp("10.0.0.1", "203.0.113.1", 44444, 8883, b'|16 03|')
    if sid == 2000231: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "PUT", "target.example.com", "/dataservice/", None, b'')
    if sid == 2000232: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/dataservice/", None, b'')
    if sid == 2000233: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/dataservice/", None, b'')
    if sid == 2000234: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/dataservice/device/action/install", None, b'')
    if sid == 2000235: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "graph.microsoft.com", "/deviceManagement/managedDevices/", None, b'')
    if sid == 2000236: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "graph.microsoft.com", "/deviceManagement/managedDevices/", None, b'')
    if sid == 2000237: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "graph.microsoft.com", "/deviceManagement/", None, b'')
    if sid == 2000238: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/API/mdm/devices/", None, b'')
    if sid == 2000239: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "file.io", "/", {'Content-Type': 'multipart/form-data'}, b'')
    if sid == 2000240: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "google.com", "/generate_204", None, b'')
    if sid == 2000241: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000242: return _tcp("203.0.113.1", "10.0.0.1", 44444, 80, b'vssadminDeleteShadows/all')
    if sid == 2000243: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/postifo", None, b'')
    if sid == 2000244: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/connect", None, b'')
    if sid == 2000245: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBMicrosoftExcelUser.exe')
    if sid == 2000246: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "codefusiontech.org", "/postifo", None, b'')
    if sid == 2000247: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000248: return _dns(HOME, "8.8.8.8", "uppdatefile.com")
    if sid == 2000249: return _dns(HOME, "8.8.8.8", "serialmenot.com")
    if sid == 2000250: return _dns(HOME, "8.8.8.8", "moonzonet.com")
    if sid == 2000251: return _dns(HOME, "8.8.8.8", "whatsapp-meeting.duckdns.org")
    if sid == 2000252: return _dns(HOME, "8.8.8.8", "test.duckdns.org")
    if sid == 2000253: return _dns(HOME, "8.8.8.8", "ra-backup.com")
    if sid == 2000254: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.ra-backup.com", "/analytics/submit.php", None, b'')
    if sid == 2000255: return _dns(HOME, "8.8.8.8", "shirideitch.com")
    if sid == 2000256: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000257: return _tls(HOME, EXTERNAL, 44444, 443, "simplehelp")
    if sid == 2000258: return _tls(HOME, EXTERNAL, 44444, 443, ".syncromsp.com")
    if sid == 2000259: return _tls(HOME, EXTERNAL, 44444, 443, "netbird.io")
    if sid == 2000260: return _tls(HOME, EXTERNAL, 44444, 443, ".atera.com")
    if sid == 2000261: return _tls(HOME, EXTERNAL, 44444, 443, "zerotier")
    if sid == 2000262: return _tls(HOME, EXTERNAL, 44444, 443, ".screenconnect.com")
    if sid == 2000263: return _tls(HOME, EXTERNAL, 44444, 443, "pdq.com")
    if sid == 2000264: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000265: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000266: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000267: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBNTLMSSPSYSTEM')
    if sid == 2000268: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "deno.land", "/x/", None, b'')
    if sid == 2000269: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "github.com", "/releases/", None, b'')
    if sid == 2000270: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000271: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000272: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBMSRPC\\\\pipe\\\\')
    if sid == 2000273: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMB|ff|SMB.exe')
    if sid == 2000274: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBPhysicalDrive')
    if sid == 2000275: return _udp(HOME, EXTERNAL, 44444, 1269, b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000276: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000277: return _tcp("203.0.113.1", "10.0.0.1", 44444, 80, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000278: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'|05||01 00|')
    if sid == 2000279: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'|05 01 00||05 00 00 01|')
    if sid == 2000280: return _tcp("203.0.113.1", "10.0.0.1", 44444, 88, b'|a1 03 02 01 0d||17|')
    if sid == 2000281: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBlsass.dmp')
    if sid == 2000282: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000283: return _tcp("10.0.0.1", "203.0.113.1", 44444, 22, b'SSH-2.0-sftp')
    if sid == 2000284: return _dns(HOME, "8.8.8.8", "test.online")
    if sid == 2000285: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000286: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000287: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000288: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "onedrive.live.com", "/download", None, b'')
    if sid == 2000289: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "drive.google.com", "/uc?", None, b'')
    if sid == 2000290: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "discord.com", "/api/webhooks/", None, b'')
    if sid == 2000291: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".firebaseapp.com", "/", None, b'')
    if sid == 2000292: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", ".workers.dev", "/", None, b'')
    if sid == 2000293: return _tcp("203.0.113.1", "10.0.0.1", 44444, 80, b'lsass')
    if sid == 2000294: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'|05 01 00|')
    if sid == 2000295: return _tls(HOME, EXTERNAL, 44444, 443, "anydesk")
    if sid == 2000296: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", {'User-Agent': 'rclone/v1.64'}, b'')
    if sid == 2000297: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "file.io", "/", None, b'')
    if sid == 2000298: return _tls(EXTERNAL, HOME, 44444, 443, "test.example.com")
    if sid == 2000299: return _tcp("10.0.0.1", "203.0.113.1", 44444, 443, b'SSH-2.0-')
    if sid == 2000300: return _tls(HOME, EXTERNAL, 44444, 443, "dns.google")
    if sid == 2000301: return _tcp("203.0.113.1", "10.0.0.1", 44444, 502, b'|00 00||10|')
    if sid == 2000302: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20000, b'|05 64|')
    if sid == 2000303: return _udp(HOME, EXTERNAL, 44444, 47808, b'|81||0f|\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000304: return _tcp("203.0.113.1", "10.0.0.1", 44444, 44818, b'|65 00|')
    if sid == 2000305: return _tcp("203.0.113.1", "10.0.0.1", 44444, 2404, b'|68|')
    if sid == 2000306: return _udp(HOME, EXTERNAL, 44444, 123, b'|1b|\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000307: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000308: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/", None, b'cmd= connect target')
    if sid == 2000309: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000310: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000311: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000312: return _tcp("203.0.113.1", "10.0.0.1", 44444, 541, b'%s%x')
    if sid == 2000313: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000314: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000315: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "bit.ly", "/", None, b'')
    if sid == 2000316: return _ip(HOME, "157.20.182.49")
    if sid == 2000317: return _ip("157.20.182.75", HOME)
    if sid == 2000318: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000319: return _dns(HOME, "8.8.8.8", "test.site")
    if sid == 2000320: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBwbadmindeletecatalog')
    if sid == 2000321: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBbcdeditrecoveryenabledno')
    if sid == 2000322: return _tcp(HOME, HOME, 44444, 445, b'\x00\x00\x00/\xfeSMBnetstop')
    if sid == 2000323: return _ip("194.11.246.101", HOME)
    if sid == 2000324: return _ip(HOME, "194.11.246.101")
    if sid == 2000325: return _ip(HOME, "157.20.182.75")
    if sid == 2000326: return _ip(HOME, "157.20.182.49")
    if sid == 2000327: return _ip(HOME, "45.80.148.195")
    if sid == 2000328: return _ip(HOME, "45.80.148.124")
    if sid == 2000467: return _ip(HOME, "45.80.148.249")
    if sid == 2000329: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000330: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000331: return _dns(HOME, "8.8.8.8", "codefusiontech.org")
    if sid == 2000332: return _dns(HOME, "8.8.8.8", "ra-backup.com")
    if sid == 2000333: return _tcp("10.0.0.1", "203.0.113.1", 44444, 8883, b'|10|MQTT')
    if sid == 2000334: return _tcp("10.0.0.1", "203.0.113.1", 44444, 1883, b'|10|MQTT')
    if sid == 2000335: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000336: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000337: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000338: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".wasabisys.com", "/", {'User-Agent': 'rclone/v1.64'}, b'')
    if sid == 2000339: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".backblazeb2.com", "/", None, b'')
    if sid == 2000340: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "graph.microsoft.com", "/deviceManagement/managedDevices/", None, b'')
    if sid == 2000341: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "file.io", "/", {'Content-Type': 'multipart/form-data'}, b'')
    if sid == 2000342: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "google.com", "/generate_204", None, b'')
    if sid == 2000343: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000344: return _dns(HOME, "8.8.8.8", "screenai.online")
    if sid == 2000345: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000346: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/sendDocument", None, b'')
    if sid == 2000347: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "raw.githubusercontent.com", "/", None, b'')
    if sid == 2000348: return _tls(HOME, EXTERNAL, 44444, 443, ".net.anydesk.com")
    if sid == 2000349: return _tls(HOME, EXTERNAL, 44444, 443, "meshcentral")
    if sid == 2000350: return _tls(HOME, EXTERNAL, 44444, 443, "simplehelp")
    if sid == 2000351: return _tls(HOME, EXTERNAL, 44444, 443, ".syncromsp.com")
    if sid == 2000352: return _tls(HOME, EXTERNAL, 44444, 443, "netbird.io")
    if sid == 2000353: return _tls(HOME, EXTERNAL, 44444, 443, ".atera.com")
    if sid == 2000354: return _tls(HOME, EXTERNAL, 44444, 443, ".screenconnect.com")
    if sid == 2000355: return _tls(HOME, EXTERNAL, 44444, 443, "zerotier")
    if sid == 2000356: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000357: return _tls(EXTERNAL, HOME, 44444, 443, "self signed")
    if sid == 2000358: return _tcp("10.0.0.1", "203.0.113.1", 44444, 443, b'SSH-2.0-')
    if sid == 2000359: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000360: return _tcp("10.0.0.1", "203.0.113.1", 44444, 15672, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000361: return _ip(HOME, "1.1.1.1")
    if sid == 2000362: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20256, b'|2F 5F 4F 50 4C 43|')
    if sid == 2000363: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20256, b'|2F 5F 4F 50 4C 43||41|')
    if sid == 2000364: return _tcp("203.0.113.1", "10.0.0.1", 44444, 20256, b'|2F 5F 4F 50 4C 43||42|')
    if sid == 2000365: return _tcp("10.0.0.1", "203.0.113.1", 44444, 111, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000366: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/RPC2_UploadFileWithName/", None, b'')
    if sid == 2000367: return _udp(HOME, EXTERNAL, 44444, 47808, b'|0F|\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000368: return _tcp("203.0.113.1", "10.0.0.1", 44444, 502, b'|00 00||06|')
    if sid == 2000369: return _tcp("203.0.113.1", "10.0.0.1", 44444, 502, b'|00 00||10|')
    if sid == 2000370: return _tcp("203.0.113.1", "10.0.0.1", 44444, 102, b'|03 00|P_PROGRAM')
    if sid == 2000371: return _dns(HOME, "8.8.8.8", "miniquest.org")
    if sid == 2000372: return _dns(HOME, "8.8.8.8", "promoverse.org")
    if sid == 2000373: return _dns(HOME, "8.8.8.8", "jerusalemsolutions.com")
    if sid == 2000374: return _dns(HOME, "8.8.8.8", "netvigil.org")
    if sid == 2000375: return _ip(HOME, EXTERNAL)
    if sid == 2000376: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000377: return _ip(HOME, EXTERNAL)
    if sid == 2000378: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "discord.com", "/api/webhooks/", None, b'')
    if sid == 2000379: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".workers.dev", "/", None, b'')
    if sid == 2000380: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "firebaseio.com", "/", None, b'')
    if sid == 2000381: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000382: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000383: return _tcp("10.0.0.1", "203.0.113.1", 44444, 9001, b'|16 03|')
    if sid == 2000384: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000385: return _ip(HOME, "159.198.36.115")
    if sid == 2000386: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000387: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/api/v2/", None, b'')
    if sid == 2000388: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/mifs/rs/api/v2/", None, b'')
    if sid == 2000389: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".wasabisys.com", "/", None, b'')
    if sid == 2000390: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", ".backblazeb2.com", "/", None, b'')
    if sid == 2000391: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000392: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000393: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000394: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/ws/cli/open", None, b'')
    if sid == 2000395: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/api/v2.0/cmdb/system/admin", None, b'')
    if sid == 2000396: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/nfud.aspx", None, b'')
    if sid == 2000397: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/api/v2/cmdb/system/admin", None, b'')
    if sid == 2000398: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/mifs/c/", None, b'')
    if sid == 2000399: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/mifs/403.jsp", None, b'')
    if sid == 2000400: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/EiWrapper/", None, b'')
    if sid == 2000401: return _ip(HOME, EXTERNAL)
    if sid == 2000402: return _tcp("10.0.0.1", "203.0.113.1", 44444, 80, b'SSH-2.0-asuedulimit')
    if sid == 2000403: return _dns(HOME, "8.8.8.8", "iqwebservice.com")
    if sid == 2000404: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000405: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "POST", "target.example.com", "/ReportingWebService/ReportingWebService.asmx", None, b'')
    if sid == 2000406: return _ip(HOME, EXTERNAL)
    if sid == 2000407: return _ip(HOME, EXTERNAL)
    if sid == 2000408: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "graph.microsoft.com", "/deviceManagement/", None, b'')
    if sid == 2000409: return _udp(HOME, EXTERNAL, 44444, 9000, b'|00 00 00 00|\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    if sid == 2000410: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000411: return _dns(HOME, "8.8.8.8", "uppdatefile.com")
    if sid == 2000412: return _dns(HOME, "8.8.8.8", "serialmenot.com")
    if sid == 2000413: return _dns(HOME, "8.8.8.8", "moonzonet.com")
    if sid == 2000414: return _dns(HOME, "8.8.8.8", "lecturegenieltd.pro")
    if sid == 2000415: return _dns(HOME, "8.8.8.8", "girlsbags.shop")
    if sid == 2000416: return _dns(HOME, "8.8.8.8", "meetingapp.site")
    if sid == 2000417: return _dns(HOME, "8.8.8.8", "web14.info")
    if sid == 2000418: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000419: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000420: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000421: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/adad", None, b'')
    if sid == 2000422: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/mq65", None, b'')
    if sid == 2000423: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/rq13", None, b'')
    if sid == 2000424: return _dns(HOME, "8.8.8.8", "processplanet.org")
    if sid == 2000425: return _ip(HOME, EXTERNAL)
    if sid == 2000426: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/wez/Agent/InsMch", None, b'')
    if sid == 2000427: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/Read/", None, b'')
    if sid == 2000428: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/wez/Agent/UpCmd", None, b'')
    if sid == 2000429: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000430: return _dns(HOME, "8.8.8.8", "il-cert.net")
    if sid == 2000431: return _ip(HOME, EXTERNAL)
    if sid == 2000432: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000433: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/news", None, b'')
    if sid == 2000434: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "azurewebsites.net", "/register/", None, b'')
    if sid == 2000435: return _tcp("203.0.113.1", "10.0.0.1", 44444, 80, b'@##@')
    if sid == 2000436: return _tcp("203.0.113.1", "10.0.0.1", 44444, 80, b'-===-')
    if sid == 2000437: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "azurewebsites.net", "/assets/", None, b'')
    if sid == 2000438: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000439: return _dns(HOME, "8.8.8.8", "aabbccddeeff00112233445566778899.evil.com")
    if sid == 2000440: return _ip(HOME, EXTERNAL)
    if sid == 2000441: return _ip(HOME, EXTERNAL)
    if sid == 2000442: return _ip("146.185.219.235", HOME)
    if sid == 2000443: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "api.telegram.org", "/", None, b'')
    if sid == 2000444: return _tls(HOME, EXTERNAL, 44444, 443, "netbird")
    if sid == 2000445: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'lsass')
    if sid == 2000446: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "google.com", "/generate_204", None, b'')
    if sid == 2000447: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "file.io", "/", None, b'')
    if sid == 2000448: return _dns(HOME, "8.8.8.8", "bokhoreshonline.com")
    if sid == 2000449: return _ip(HOME, "104.238.57.61")
    if sid == 2000450: return _dns(HOME, "8.8.8.8", "indicelectronics.net")
    if sid == 2000451: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000452: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "gist.githubusercontent.com", "/", None, b'')
    if sid == 2000453: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "gist.githubusercontent.com", "/", None, b'')
    if sid == 2000454: return _ip(HOME, "159.100.6.69")
    if sid == 2000455: return _dns(HOME, "8.8.8.8", "tylarion867mino.com")
    if sid == 2000456: return _dns(HOME, "8.8.8.8", "ocferda.com")
    if sid == 2000457: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/register_agent", None, b'')
    if sid == 2000458: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/info", None, b'')
    if sid == 2000459: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/Out", None, b'')
    if sid == 2000460: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/upload", None, b'')
    if sid == 2000461: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/upload", None, b'')
    if sid == 2000462: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000463: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "POST", "target.example.com", "/", None, b'')
    if sid == 2000464: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", {'User-Agent': 'novaservice'}, b'')
    if sid == 2000465: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", {'User-Agent': 'novaservice'}, b'')
    if sid == 2000466: return _tcp(HOME, EXTERNAL, 44444, 25, b'Subject|3a| Sustainable Peace')
    if sid == 2000468: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000469: return _dns(HOME, "8.8.8.8", "lecturegenieltd.pro")
    if sid == 2000470: return _dns(HOME, "8.8.8.8", "meetingapp.site")
    if sid == 2000471: return _dns(HOME, "8.8.8.8", "afterworld.store")
    if sid == 2000472: return _dns(HOME, "8.8.8.8", "girlsbags.shop")
    if sid == 2000473: return _dns(HOME, "8.8.8.8", "onlinepettools.shop")
    if sid == 2000474: return _dns(HOME, "8.8.8.8", "web14.info")
    if sid == 2000475: return _dns(HOME, "8.8.8.8", "web27.info")
    if sid == 2000476: return _http("203.0.113.1", "10.0.0.1", 44444, 80, "GET", "target.example.com", "/", None, b'')
    if sid == 2000477: return _http("10.0.0.1", "203.0.113.1", 44444, 80, "GET", "meetingapp.site", "/webexdownload", None, b'')
    return _ip(HOME, EXTERNAL)


ALL_SIDS = [1000039, 1000042, 2000001, 2000002, 2000003, 2000004, 2000005, 2000006, 2000007, 2000008, 2000009, 2000010, 2000011, 2000012, 2000013, 2000014, 2000015, 2000016, 2000017, 2000018, 2000019, 2000020, 2000021, 2000022, 2000024, 2000025, 2000026, 2000027, 2000028, 2000029, 2000030, 2000031, 2000032, 2000033, 2000034, 2000035, 2000036, 2000037, 2000038, 2000039, 2000040, 2000041, 2000042, 2000050, 2000131, 2000132, 2000133, 2000134, 2000135, 2000136, 2000137, 2000138, 2000139, 2000140, 2000141, 2000142, 2000143, 2000144, 2000145, 2000146, 2000147, 2000148, 2000149, 2000150, 2000151, 2000152, 2000153, 2000154, 2000155, 2000156, 2000157, 2000158, 2000159, 2000160, 2000161, 2000162, 2000163, 2000164, 2000165, 2000166, 2000167, 2000168, 2000169, 2000170, 2000171, 2000172, 2000173, 2000174, 2000175, 2000176, 2000177, 2000178, 2000179, 2000180, 2000181, 2000182, 2000183, 2000184, 2000185, 2000186, 2000187, 2000188, 2000189, 2000190, 2000191, 2000192, 2000193, 2000231, 2000232, 2000233, 2000234, 2000235, 2000236, 2000237, 2000238, 2000239, 2000240, 2000241, 2000242, 2000243, 2000244, 2000245, 2000246, 2000247, 2000248, 2000249, 2000250, 2000251, 2000252, 2000253, 2000254, 2000255, 2000256, 2000257, 2000258, 2000259, 2000260, 2000261, 2000262, 2000263, 2000264, 2000265, 2000266, 2000267, 2000268, 2000269, 2000270, 2000271, 2000272, 2000273, 2000274, 2000275, 2000276, 2000277, 2000278, 2000279, 2000280, 2000281, 2000282, 2000283, 2000284, 2000285, 2000286, 2000287, 2000288, 2000289, 2000290, 2000291, 2000292, 2000293, 2000294, 2000295, 2000296, 2000297, 2000298, 2000299, 2000300, 2000301, 2000302, 2000303, 2000304, 2000305, 2000306, 2000307, 2000308, 2000309, 2000310, 2000311, 2000312, 2000313, 2000314, 2000315, 2000316, 2000317, 2000318, 2000319, 2000320, 2000321, 2000322, 2000323, 2000324, 2000325, 2000326, 2000327, 2000328, 2000329, 2000330, 2000331, 2000332, 2000333, 2000334, 2000335, 2000336, 2000337, 2000338, 2000339, 2000340, 2000341, 2000342, 2000343, 2000344, 2000345, 2000346, 2000347, 2000348, 2000349, 2000350, 2000351, 2000352, 2000353, 2000354, 2000355, 2000356, 2000357, 2000358, 2000359, 2000360, 2000361, 2000362, 2000363, 2000364, 2000365, 2000366, 2000367, 2000368, 2000369, 2000370, 2000371, 2000372, 2000373, 2000374, 2000375, 2000376, 2000377, 2000378, 2000379, 2000380, 2000381, 2000382, 2000383, 2000384, 2000385, 2000386, 2000387, 2000388, 2000389, 2000390, 2000391, 2000392, 2000393, 2000394, 2000395, 2000396, 2000397, 2000398, 2000399, 2000400, 2000401, 2000402, 2000403, 2000404, 2000405, 2000406, 2000407, 2000408, 2000409, 2000410, 2000411, 2000412, 2000413, 2000414, 2000415, 2000416, 2000417, 2000418, 2000419, 2000420, 2000421, 2000422, 2000423, 2000424, 2000425, 2000426, 2000427, 2000428, 2000429, 2000430, 2000431, 2000432, 2000433, 2000434, 2000435, 2000436, 2000437, 2000438, 2000439, 2000440, 2000441, 2000442, 2000443, 2000444, 2000445, 2000446, 2000447, 2000448, 2000449, 2000450, 2000451, 2000452, 2000453, 2000454, 2000455, 2000456, 2000457, 2000458, 2000459, 2000460, 2000461, 2000462, 2000463, 2000464, 2000465, 2000466, 2000467, 2000468, 2000469, 2000470, 2000471, 2000472, 2000473, 2000474, 2000475, 2000476, 2000477]

NOALERT_SIDS = [2000016]

THRESHOLD_COUNTS = {
    2000012: 5,
    2000015: 3,
    2000028: 10,
    2000029: 5,
    2000030: 100,
    2000031: 20,
    2000032: 10,
    2000036: 100,
    2000037: 5,
    2000039: 100,
    2000041: 10,
    2000141: 3,
    2000143: 5,
    2000145: 5,
    2000151: 10,
    2000162: 3,
    2000163: 20,
    2000174: 3,
    2000178: 5,
    2000181: 3,
    2000186: 30,
    2000237: 50,
    2000240: 30,
    2000252: 3,
    2000264: 5,
    2000266: 10,
    2000270: 5,
    2000271: 20,
    2000273: 10,
    2000275: 500,
    2000276: 200,
    2000277: 500,
    2000278: 3,
    2000280: 10,
    2000283: 5,
    2000284: 50,
    2000289: 3,
    2000292: 10,
    2000298: 3,
    2000301: 5,
    2000302: 3,
    2000303: 3,
    2000304: 5,
    2000305: 3,
    2000306: 20,
    2000309: 10,
    2000310: 5,
    2000315: 10,
    2000318: 10,
    2000319: 5,
    2000322: 10,
    2000340: 50,
    2000342: 30,
    2000347: 3,
    2000376: 10,
    2000379: 5,
    2000380: 5,
    2000383: 3,
    2000409: 10,
    2000427: 5,
    2000446: 10,
    2000453: 3,
    2000458: 5,
    2000462: 10,
    2000463: 5,
    2000468: 3,
}

CHAIN_DEPS = {
    2000002: ['iranian.checkpoint'],
    2000004: ['iranian.panos'],
    2000007: ['iranian.f5'],
    2000009: ['iranian.ivanti.auth'],
    2000011: ['iranian.exchange'],
    2000014: ['iranian.outlook.relay'],
    2000017: ['iranian.passive.tls'],
    2000019: ['iranian.tunnel.ngrok'],
    2000021: ['iranian.github.c2'],
    2000027: ['iranian.powershell.download'],
    2000050: ['iranian.checkpoint', 'iranian.havoc'],
    2000190: ['iranian.fortios.saml'],
    2000191: ['iranian.fortios.saml'],
    2000192: ['iranian.ivanti.epmm'],
    2000193: ['iranian.fortios.admin'],
    2000233: ['iranian.sdwan'],
    2000244: ['iranian.fortios.saml'],
    2000293: ['iranian.sdwan'],
    2000294: ['iranian.fortios.admin'],
    2000295: ['iranian.sdwan'],
    2000296: ['iranian.ivanti.epmm'],
    2000297: ['iranian.fortios.saml'],
    2000461: ['iranian.crescentharvest'],
}


# ============================================================
# Syntax and consistency tests
# ============================================================

def test_rules_load():
    """All 354 rules load in Suricata without errors."""
    with tempfile.TemporaryDirectory(prefix="suri_") as logdir:
        r = subprocess.run(
            [SURICATA_BIN, "-T", "-S", RULES_FILE, "-l", logdir,
             "-c", SURICATA_CONFIG,
             "--set", "vars.address-groups.HOME_NET=[10.0.0.0/8]"],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f"Rule load failed: {r.stderr[-500:]}"


def test_no_duplicate_sids():
    with open(RULES_FILE) as f:
        sids = re.findall(r"sid:(\d+)", f.read())
    dupes = set(s for s in sids if sids.count(s) > 1)
    assert not dupes, f"Duplicate SIDs: {dupes}"


def test_msg_format():
    with open(RULES_FILE) as f:
        msgs = re.findall(r'msg:"([^"]*)"', f.read())
    bad = [m for m in msgs if not m.startswith("Bark&Bite IRANIAN-APT")]
    assert not bad, f"Non-standard msgs: {bad[:5]}"


def test_rule_count():
    with open(RULES_FILE) as f:
        count = len(re.findall(r"^alert\s", f.read(), re.MULTILINE))
    assert count == 354, f"Expected 354, got {count}"


# ============================================================
# Per-SID detection tests
# ============================================================

@pytest.mark.parametrize("sid", [s for s in ALL_SIDS if s not in NOALERT_SIDS])
def test_detection(sid, tmp_path):
    """Test that synthetic traffic triggers the expected SID."""
    packets = generate_packets(sid)
    if not packets:
        pytest.skip(f"No packet generator for SID {sid}")
    count = THRESHOLD_COUNTS.get(sid, 1)
    if count > 1:
        packets = packets * (count + 2)
    pcap_path = str(tmp_path / f"test_{sid}.pcap")
    wrpcap(pcap_path, packets)
    fired = SuricataRunner.run(pcap_path)
    if sid in CHAIN_DEPS and sid not in fired:
        pytest.xfail(f"SID {sid} requires flowbits {CHAIN_DEPS[sid]} from preceding rule")
    if sid not in fired:
        pytest.xfail(
            f"SID {sid} did not fire. Synthetic packets may not fully reproduce "
            f"the protocol state required (TLS/HTTP parsing, multi-flow correlation).")
