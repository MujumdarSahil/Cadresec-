from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class OpenSSHDetector(BaseDetector):
    name = "OpenSSH"
    category = TechnologyCategory.SERVICE
    rules = [
        (EvidenceType.BANNER, r"(?i)ssh-([\d\.]+)-openssh_([\d\.]+)", 1.0, r"(?i)openssh_([\d\.]+)")
    ]
