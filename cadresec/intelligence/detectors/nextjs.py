from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class NextJSDetector(BaseDetector):
    name = "Next.js"
    category = TechnologyCategory.FRAMEWORK
    rules = [
        (EvidenceType.HTML, r"(?i)/_next/static/", 0.95, None),
        (EvidenceType.HEADER, r"(?i)x-nextjs-cache", 0.99, None),
        (EvidenceType.COOKIE, r"(?i)__next_preview_data", 0.95, None)
    ]
