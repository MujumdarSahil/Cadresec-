from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class JQueryDetector(BaseDetector):
    name = "jQuery"
    category = TechnologyCategory.LIBRARY
    rules = [
        (EvidenceType.SCRIPT, r"(?i)jquery(?:-([\d\.]+))?(?:\.min)?\.js", 0.9, r"(?i)jquery(?:-([\d\.]+))?")
    ]
