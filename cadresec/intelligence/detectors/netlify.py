from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class NetlifyDetector(BaseDetector):
    name = "Netlify"
    category = TechnologyCategory.CLOUD
    rules = [
        (EvidenceType.HEADER, r"(?i)server:\s*netlify", 0.95, None)
    ]
