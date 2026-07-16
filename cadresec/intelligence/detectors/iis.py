from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class IISDetector(BaseDetector):
    name = "IIS"
    category = TechnologyCategory.SERVER
    rules = [
        (EvidenceType.SERVER, r"(?i)microsoft-iis(?:/([\d\.]+))?", 1.0, r"(?i)iis/([\d\.]+)")
    ]
