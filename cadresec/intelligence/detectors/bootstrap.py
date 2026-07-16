from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class BootstrapDetector(BaseDetector):
    name = "Bootstrap"
    category = TechnologyCategory.CSS
    rules = [
        (EvidenceType.HTML, r"(?i)class=.*container.*col-", 0.5, None)
    ]
