import os
import socket
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError
from cadresec.core.evidence import Evidence
from cadresec.intelligence.fingerprint_engine import FingerprintEngine, TechnologyProfile

# OCSF Models
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService, OCSFVulnerabilityFinding, FindingInfo, Vulnerability

# Tools
from cadresec.tools.nmap import NmapToolSpec
from cadresec.tools.http_probe import HTTPProbeToolSpec
from cadresec.tools.dns_lookup import DNSLookupToolSpec, DNSInput, DNSOutput
from cadresec.tools.banner_grab import BannerGrabToolSpec, BannerGrabInput, BannerGrabOutput

# Agents
from cadresec.agents.recon import build_recon_graph, recon_node
from cadresec.agents.tech_intel import build_tech_intel_graph, tech_intel_node
from cadresec.agents.vuln import build_vuln_graph, vuln_node
from cadresec.agents.research import build_research_graph, research_node


MOCK_NMAP_OUTPUT = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -F 127.0.0.1" start="1700000000" version="7.92">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" method="table"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def session(valid_roe):
    return EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)


# --- 1. Evidence Model Tests ---

def test_evidence_model_creation():
    ev = Evidence(
        category="server",
        value="nginx/1.25.1",
        confidence=0.99,
        source="HTTP Header",
        originating_tool="http_probe"
    )
    assert ev.category == "server"
    assert ev.value == "nginx/1.25.1"
    assert ev.confidence == 0.99
    assert ev.source == "HTTP Header"
    assert ev.originating_tool == "http_probe"
    assert ev.timestamp is not None


# --- 2. Fingerprint Engine Tests ---

def test_fingerprint_engine_web_server_detection():
    engine = FingerprintEngine()
    evidence = [
        Evidence(category="server", value="nginx/1.25.1", confidence=1.0, source="HTTP Header", originating_tool="http_probe"),
        Evidence(category="cookie", value="next-auth.session-token", confidence=1.0, source="Cookie", originating_tool="http_probe")
    ]
    profiles = engine.analyze(evidence)
    assert len(profiles) >= 2
    
    # Check Nginx
    nginx_prof = next(p for p in profiles if p.technology == "Nginx")
    assert nginx_prof.category == "Web Server"
    assert nginx_prof.version == "1.25.1"
    assert nginx_prof.confidence == 1.0
    
    # Check NextAuth.js
    auth_prof = next(p for p in profiles if p.technology == "NextAuth.js")
    assert auth_prof.category == "Authentication Provider"
    assert auth_prof.confidence == 1.0


# --- 3. DNS Lookup Tool Tests ---

def test_dns_lookup_enforces_scope(session):
    dns_tool = DNSLookupToolSpec()
    # 10.0.0.1 is out of scope by default in valid_roe fixture
    with pytest.raises(ScopeViolationError):
        dns_tool.run(session, DNSInput(target="10.0.0.1"))


@patch("dns.resolver.Resolver.resolve")
def test_dns_lookup_resolves_mocked_records(mock_resolve, session):
    dns_tool = DNSLookupToolSpec()
    
    mock_answer = MagicMock()
    mock_answer.__str__.return_value = "1.2.3.4"
    mock_resolve.return_value = [mock_answer]
    
    output = dns_tool.run(session, DNSInput(target="exact-domain.com", record_types=["A"]))
    assert output.success is True
    assert "A" in output.records
    assert output.records["A"] == ["1.2.3.4"]
    assert len(output.evidence) == 1
    assert output.evidence[0].category == "dns"
    assert output.evidence[0].value == "A:1.2.3.4"
    
    # Verify OCSF Event
    events = session.ocsf.read_events(session.session_id, class_uid=5010)
    assert len(events) == 1
    assert events[0]["device"]["hostname"] == "exact-domain.com"


# --- 4. Banner Grab Tool Tests ---

def test_banner_grab_enforces_scope(session):
    banner_tool = BannerGrabToolSpec()
    with pytest.raises(ScopeViolationError):
        banner_tool.run(session, BannerGrabInput(target="10.0.0.1", port=22))


def test_banner_grab_enforces_approval(valid_roe):
    # Reject callback
    session_reject = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: False)
    banner_tool = BannerGrabToolSpec()
    with pytest.raises(ApprovalViolationError):
        banner_tool.run(session_reject, BannerGrabInput(target="127.0.0.1", port=22))


@patch("socket.create_connection")
def test_banner_grab_reads_banner(mock_create, session):
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1"
    mock_socket.__enter__.return_value = mock_socket
    mock_create.return_value = mock_socket
    
    banner_tool = BannerGrabToolSpec()
    output = banner_tool.run(session, BannerGrabInput(target="127.0.0.1", port=22))
    
    assert output.success is True
    assert output.banner == "SSH-2.0-OpenSSH_8.9p1"
    assert output.service_guess == "ssh"
    assert len(output.evidence) == 2
    assert output.evidence[0].category == "banner"
    assert output.evidence[0].value == "SSH-2.0-OpenSSH_8.9p1"
    assert output.evidence[1].category == "server"
    assert output.evidence[1].value == "ssh"
    
    # Check OCSF logs
    network_events = session.ocsf.read_events(session.session_id, class_uid=4001)
    discovery_events = session.ocsf.read_events(session.session_id, class_uid=5010)
    
    assert len(network_events) == 1
    assert len(discovery_events) == 1
    assert discovery_events[0]["device"]["services"][0]["service"] == "ssh"


@patch("socket.create_connection", side_effect=socket.timeout)
def test_banner_grab_handles_timeout(mock_create, session):
    banner_tool = BannerGrabToolSpec()
    output = banner_tool.run(session, BannerGrabInput(target="127.0.0.1", port=22))
    assert output.success is False
    assert output.banner == ""


# --- 5. Domain Agent Tests ---

@patch("subprocess.run")
@patch("socket.create_connection")
def test_recon_agent_runs_workflow(mock_socket, mock_sub, session):
    # Setup Nmap Mock
    mock_proc = MagicMock()
    mock_proc.stdout = MOCK_NMAP_OUTPUT
    mock_proc.returncode = 0
    mock_sub.return_value = mock_proc

    # Setup Banner Mock
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1"
    mock_sock.__enter__.return_value = mock_sock
    mock_socket.return_value = mock_sock

    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config = {"configurable": {"session": session}}
    
    with patch.object(NmapToolSpec, "_is_docker_available", return_value=True):
        with patch.object(BannerGrabToolSpec, "_is_docker_available", return_value=True):
            result = recon_node(initial_state, config)
            
            assert "recon" in result["completed_steps"]
            messages = result["messages"]
            assert any("Resolved IPs" in m["text"] for m in messages)
            assert any("Nmap discovery scan completed" in m["text"] for m in messages)


@patch("subprocess.run")
def test_tech_intel_agent_runs_workflow(mock_sub, session):
    # Mock HTTP Probe curl stdout to yield Next.js headers & Server header
    mock_proc = MagicMock()
    mock_proc.stdout = "HTTP/1.1 200 OK\r\nServer: Cloudflare\r\nX-Nextjs-Cache: HIT\r\n\r\n__CADRESEC_METADATA_START__\n{\"http_code\": 200, \"time_total\": 0.1}\n__CADRESEC_METADATA_END__"
    mock_proc.returncode = 0
    mock_sub.return_value = mock_proc

    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config = {"configurable": {"session": session}}
    
    with patch.object(HTTPProbeToolSpec, "_is_docker_available", return_value=True):
        result = tech_intel_node(initial_state, config)
        
        assert "tech_intel" in result["completed_steps"]
        msg_text = result["messages"][0]["text"]
        assert "Cloudflare" in msg_text
        assert "Next.js" in msg_text


@patch("socket.create_connection")
def test_vulnerability_agent_runs_workflow(mock_socket, session):
    # Setup mock open port in OCSF so SSL check is run
    discovery = OCSFDiscovery(
        device=DiscoveryDevice(
            ip="127.0.0.1",
            services=[DiscoveredService(port=443, protocol="TCP", service="https", state="open")]
        ),
        session_id=session.session_id
    )
    session.ocsf.write_event(session.session_id, 5010, discovery)

    # Mock SSL Peer Certificate returning an expired date or soon-expiring date
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_socket.return_value = mock_sock
    
    # We patch ssl_check datetime to verify expiry
    with patch("ssl.create_default_context") as mock_ssl:
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"notAfter": "Jul 20 12:00:00 2026 GMT"}
        mock_ssl.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        initial_state = {
            "current_target": "127.0.0.1",
            "messages": [],
            "completed_steps": [],
            "routing_decision": ""
        }
        config = {"configurable": {"session": session}}
        result = vuln_node(initial_state, config)
        
        assert "vuln_analysis" in result["completed_steps"]
        
        # Verify OCSFVulnerabilityFinding (class_uid 2002) is written
        findings = session.ocsf.read_events(session.session_id, class_uid=2002)
        assert len(findings) > 0
        assert any("SSL Certificate Near Expiry" in f["finding_info"]["title"] for f in findings)


def test_research_agent_compiles_interface_graph(session):
    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    config = {"configurable": {"session": session}}
    result = research_node(initial_state, config)
    
    assert "research_interface" in result["completed_steps"]
    assert "Research Agent interface initialized" in result["messages"][0]["text"]
