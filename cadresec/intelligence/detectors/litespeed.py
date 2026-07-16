from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class LiteSpeedDetector(BaseDetector):
    name = "LiteSpeed"
    category = TechnologyCategory.SERVER
    rules = [
        (EvidenceType.SERVER, r"(?i)litespeed", 1.0, None)
    ]
