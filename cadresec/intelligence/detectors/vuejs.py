from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class VueJSDetector(BaseDetector):
    name = "Vue.js"
    category = TechnologyCategory.FRAMEWORK
    rules = [
        (EvidenceType.HTML, r"(?i)data-v-[a-f\d]+|__vue__", 0.9, None)
    ]
