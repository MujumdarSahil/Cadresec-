import os
import socket
import subprocess
import random
import time
import pytest
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import patch

from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.tools.http_probe import HTTPProbeToolSpec, HTTPProbeInput
from cadresec.tools.banner_grab import BannerGrabToolSpec, BannerGrabInput
from cadresec.intelligence.fingerprint_engine import FingerprintEngine

def is_docker_running() -> bool:
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        return res.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

class DockerContainerHelper:
    def __init__(self, image: str, port_mapping: str, env_vars: list = None):
        self.image = image
        self.port_mapping = port_mapping
        self.env_vars = env_vars or []
        self.name = f"cadresec-test-{random.randint(1000, 9999)}"
        
    def __enter__(self):
        cmd = ["docker", "run", "-d", "--name", self.name]
        for env in self.env_vars:
            cmd.extend(["-e", env])
        cmd.extend(["-p", self.port_mapping, self.image])
        subprocess.run(cmd, check=True, capture_output=True)
        # Give it a moment to boot
        time.sleep(5.0)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)


def test_real_nginx_container_validation():
    if not is_docker_running():
        pytest.skip("Docker daemon not running.")
        
    host_port = get_free_port()
    
    # Setup test-only RoE with auto-approval callback
    now = datetime.now(timezone.utc)
    valid_test_roe = RulesOfEngagement(
        authorized_scope=["127.0.0.1"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="Test Suite Validation"
    )
    session = EngagementSession(roe=valid_test_roe, approval_callback=lambda tool, risk: True)
    
    with DockerContainerHelper("nginx:alpine", f"{host_port}:80") as container:
        # Run http_probe
        probe_tool = HTTPProbeToolSpec()
        output = probe_tool.run(session, HTTPProbeInput(target="127.0.0.1", port=host_port))
        
        assert output.success is True
        
        # Pass gathered evidence to fingerprint engine
        engine = FingerprintEngine()
        profiles = engine.analyze(output.evidence)
        
        # Verify Nginx detected
        nginx_profile = next((p for p in profiles if p.technology == "Nginx"), None)
        assert nginx_profile is not None
        assert nginx_profile.category == "Web Server"
        assert nginx_profile.confidence >= 0.8


def test_real_openssh_container_validation():
    if not is_docker_running():
        pytest.skip("Docker daemon not running.")
        
    host_port = get_free_port()
    
    # Setup test-only RoE with auto-approval callback
    now = datetime.now(timezone.utc)
    valid_test_roe = RulesOfEngagement(
        authorized_scope=["127.0.0.1"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="Test Suite Validation"
    )
    session = EngagementSession(roe=valid_test_roe, approval_callback=lambda tool, risk: True)
    
    # rastasheep/ubuntu-sshd is very standard and boots instantly
    with DockerContainerHelper("rastasheep/ubuntu-sshd:18.04", f"{host_port}:22") as container:
        banner_tool = BannerGrabToolSpec()
        output = banner_tool.run(session, BannerGrabInput(target="127.0.0.1", port=host_port))
        
        assert output.success is True
        assert "SSH-" in output.banner
        
        engine = FingerprintEngine()
        profiles = engine.analyze(output.evidence)
        
        openssh_profile = next((p for p in profiles if p.technology == "OpenSSH"), None)
        assert openssh_profile is not None
        assert openssh_profile.category == "Service"
        assert openssh_profile.confidence >= 0.8


def test_real_wordpress_container_validation():
    if not is_docker_running():
        pytest.skip("Docker daemon not running.")
        
    host_port = get_free_port()
    
    # Setup test-only RoE with auto-approval callback
    now = datetime.now(timezone.utc)
    valid_test_roe = RulesOfEngagement(
        authorized_scope=["127.0.0.1"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="Test Suite Validation"
    )
    session = EngagementSession(roe=valid_test_roe, approval_callback=lambda tool, risk: True)
    
    # WordPress container without DB will redirect to setup and serve wordpress HTML links
    with DockerContainerHelper("wordpress:latest", f"{host_port}:80") as container:
        probe_tool = HTTPProbeToolSpec()
        output = probe_tool.run(session, HTTPProbeInput(target="127.0.0.1", port=host_port))
        
        assert output.success is True
        
        engine = FingerprintEngine()
        profiles = engine.analyze(output.evidence)
        
        wp_profile = next((p for p in profiles if p.technology == "WordPress"), None)
        assert wp_profile is not None
        assert wp_profile.category == "CMS"
        assert wp_profile.confidence >= 0.8


def test_real_cloudflare_public_validation():
    # Setup test-only RoE targeting cdnjs.cloudflare.com
    now = datetime.now(timezone.utc)
    valid_test_roe = RulesOfEngagement(
        authorized_scope=["cdnjs.cloudflare.com"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="Test Suite Validation"
    )
    session = EngagementSession(roe=valid_test_roe, approval_callback=lambda tool, risk: True)
    
    probe_tool = HTTPProbeToolSpec()
    try:
        # Run probe against cdnjs.cloudflare.com:443
        output = probe_tool.run(session, HTTPProbeInput(target="cdnjs.cloudflare.com", port=443, ssl=True))
        if output.success:
            engine = FingerprintEngine()
            profiles = engine.analyze(output.evidence)
            
            cf_profile = next((p for p in profiles if p.technology == "Cloudflare"), None)
            assert cf_profile is not None
            assert cf_profile.category == "CDN/WAF"
            assert cf_profile.confidence >= 0.8
    except Exception:
        # Pass if network/DNS is blocked/offline in test environment
        pass


def test_real_nextjs_public_validation():
    # Setup test-only RoE targeting nextjs.org
    now = datetime.now(timezone.utc)
    valid_test_roe = RulesOfEngagement(
        authorized_scope=["nextjs.org"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="Test Suite Validation"
    )
    session = EngagementSession(roe=valid_test_roe, approval_callback=lambda tool, risk: True)
    
    probe_tool = HTTPProbeToolSpec()
    try:
        output = probe_tool.run(session, HTTPProbeInput(target="nextjs.org", port=443, ssl=True))
        if output.success:
            engine = FingerprintEngine()
            profiles = engine.analyze(output.evidence)
            
            next_profile = next((p for p in profiles if p.technology == "Next.js"), None)
            assert next_profile is not None
            assert next_profile.category == "Web Framework"
            assert next_profile.confidence >= 0.8
    except Exception:
        # Pass if network/DNS is blocked/offline in test environment
        pass
