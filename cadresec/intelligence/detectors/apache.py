from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class ApacheDetector(BaseDetector):
    name = "Apache"
    category = TechnologyCategory.SERVER
    rules = [
        (EvidenceType.SERVER, r"(?i)apache(?:/([\d\.]+))?", 1.0, r"(?i)apache/([\d\.]+)")
    ]
