from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class ReactDetector(BaseDetector):
    name = "React"
    category = TechnologyCategory.FRAMEWORK
    rules = [
        (EvidenceType.HTML, r"(?i)data-reactroot|react-root|__react", 0.9, None)
    ]
