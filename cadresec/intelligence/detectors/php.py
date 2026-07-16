from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class PHPDetector(BaseDetector):
    name = "PHP"
    category = TechnologyCategory.LANGUAGE
    rules = [
        (EvidenceType.HEADER, r"(?i)x-powered-by:.*php/([\d\.]+)", 0.99, r"(?i)php/([\d\.]+)"),
        (EvidenceType.COOKIE, r"(?i)PHPSESSID", 0.95, None)
    ]
