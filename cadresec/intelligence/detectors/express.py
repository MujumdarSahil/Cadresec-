from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class ExpressDetector(BaseDetector):
    name = "Express"
    category = TechnologyCategory.BACKEND
    rules = [
        (EvidenceType.HEADER, r"(?i)x-powered-by:.*express", 0.9, None)
    ]
