from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class VercelDetector(BaseDetector):
    name = "Vercel"
    category = TechnologyCategory.CLOUD
    rules = [
        (EvidenceType.HEADER, r"(?i)x-vercel-", 0.95, None)
    ]
