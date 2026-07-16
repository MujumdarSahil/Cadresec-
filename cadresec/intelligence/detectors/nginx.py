from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class NginxDetector(BaseDetector):
    name = "Nginx"
    category = TechnologyCategory.SERVER
    rules = [
        (EvidenceType.SERVER, r"(?i)nginx(?:/([\d\.]+))?", 1.0, r"(?i)nginx/([\d\.]+)")
    ]
