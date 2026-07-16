from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class TailwindDetector(BaseDetector):
    name = "Tailwind CSS"
    category = TechnologyCategory.CSS
    rules = [
        (EvidenceType.HTML, r"(?i)class=.*space-y-|bg-[\w]+-\d+", 0.5, None)
    ]
