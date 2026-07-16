from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class CaddyDetector(BaseDetector):
    name = "Caddy"
    category = TechnologyCategory.SERVER
    rules = [
        (EvidenceType.SERVER, r"(?i)caddy(?:/([\d\.]+))?", 1.0, r"(?i)caddy/([\d\.]+)")
    ]
