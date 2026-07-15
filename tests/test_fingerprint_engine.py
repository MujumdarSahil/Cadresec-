import pytest
from datetime import datetime, timezone
from cadresec.intelligence.enums import EvidenceType, TechnologyCategory
from cadresec.intelligence.evidence import Evidence
from cadresec.intelligence.models import TechnologyProfile
from cadresec.intelligence.engine import FingerprintEngine
from cadresec.intelligence.registry import DetectorRegistry
from cadresec.intelligence.detectors.base import BaseDetector


def test_evidence_and_technology_profile_enums():
    # Test EvidenceType enum
    assert EvidenceType.HEADER == "header"
    assert EvidenceType.COOKIE == "cookie"
    assert EvidenceType.HTTP_CODE == "http_code"
    
    # Test TechnologyCategory enum
    assert TechnologyCategory.SERVER == "Web Server"
    assert TechnologyCategory.CMS == "CMS"


def test_evidence_model_with_datetime():
    ts_str = "2026-07-15T23:53:14.000Z"
    ev = Evidence(
        category="cookie",
        value="PHPSESSID=abc",
        confidence=0.95,
        source="Cookie",
        timestamp=ts_str,
        originating_tool="http_probe"
    )
    # Verify parsing string into datetime
    assert isinstance(ev.timestamp, datetime)
    assert ev.category == EvidenceType.COOKIE


def test_registry_loading():
    detectors = DetectorRegistry.load_detectors()
    assert len(detectors) > 0
    # Ensure all are subclasses of BaseDetector
    for d in detectors:
        assert issubclass(d, BaseDetector)
    
    # Check that NginxDetector is in the list
    names = [d.name for d in detectors]
    assert "Nginx" in names
    assert "WordPress" in names


def test_engine_analyze_single_match():
    engine = FingerprintEngine()
    evidence = [
        Evidence(
            category="server",
            value="nginx/1.25.1",
            confidence=1.0,
            source="HTTP Header",
            originating_tool="http_probe"
        )
    ]
    profiles = engine.analyze(evidence)
    assert len(profiles) > 0
    
    nginx_prof = next(p for p in profiles if p.name == "Nginx")
    assert nginx_prof.category == "Web Server"
    assert nginx_prof.version == "1.25.1"
    assert nginx_prof.confidence == 1.0


def test_engine_noisy_or_confidence():
    engine = FingerprintEngine()
    # Feed two separate evidence items that match Cloudflare
    evidence = [
        Evidence(
            category="server",
            value="cloudflare",
            confidence=1.0,
            source="HTTP Header",
            originating_tool="http_probe"
        ),
        Evidence(
            category="header",
            value="cf-ray: 123456",
            confidence=0.95,
            source="HTTP Header",
            originating_tool="http_probe"
        )
    ]
    profiles = engine.analyze(evidence)
    cf_prof = next(p for p in profiles if p.name == "Cloudflare")
    # Noisy-OR calculation: 1.0 - (1.0 - 1.0) * (1.0 - 0.95) = 1.0
    assert cf_prof.confidence == 1.0

    # Feed two separate matches with confidence < 1.0
    evidence_php = [
        Evidence(
            category="header",
            value="x-powered-by: PHP/8.1",
            confidence=0.99,
            source="HTTP Header",
            originating_tool="http_probe"
        ),
        Evidence(
            category="cookie",
            value="PHPSESSID=abc",
            confidence=0.95,
            source="Cookie",
            originating_tool="http_probe"
        )
    ]
    profiles_php = engine.analyze(evidence_php)
    php_prof = next(p for p in profiles_php if p.name == "PHP")
    # Noisy-OR calculation: 1.0 - (1.0 - 0.99) * (1.0 - 0.95) = 1.0 - 0.01 * 0.05 = 0.9995
    assert php_prof.confidence == 0.9995
    assert php_prof.version == "8.1"


def test_negative_match():
    engine = FingerprintEngine()
    # Feed evidence that shouldn't match Django
    evidence = [
        Evidence(
            category="cookie",
            value="some_random_cookie=abc",
            confidence=0.5,
            source="Cookie",
            originating_tool="http_probe"
        )
    ]
    profiles = engine.analyze(evidence)
    # Verify Django is not matched
    django_matches = [p for p in profiles if p.name == "Django"]
    assert len(django_matches) == 0
