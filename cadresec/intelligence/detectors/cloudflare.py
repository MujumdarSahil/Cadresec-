from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class CloudflareDetector(BaseDetector):
    name = "Cloudflare"
    category = TechnologyCategory.CDN
    rules = [
        (EvidenceType.SERVER, r"(?i)cloudflare", 1.0, None),
        (EvidenceType.HEADER, r"(?i)cf-ray|cf-cache-status", 0.95, None)
    ]
