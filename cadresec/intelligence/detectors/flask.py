from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class FlaskDetector(BaseDetector):
    name = "Flask"
    category = TechnologyCategory.BACKEND
    rules = [
        (EvidenceType.HEADER, r"(?i)server:\s*werkzeug", 0.9, None),
        (EvidenceType.COOKIE, r"(?i)session", 0.1, None)
    ]
