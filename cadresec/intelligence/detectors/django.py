from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class DjangoDetector(BaseDetector):
    name = "Django"
    category = TechnologyCategory.BACKEND
    rules = [
        (EvidenceType.COOKIE, r"(?i)csrftoken", 0.7, None),
        (EvidenceType.HTML, r"(?i)csrfmiddlewaretoken", 0.9, None)
    ]
