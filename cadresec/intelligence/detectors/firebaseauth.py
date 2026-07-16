from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class FirebaseAuthDetector(BaseDetector):
    name = "Firebase Auth"
    category = TechnologyCategory.AUTH
    rules = [
        (EvidenceType.COOKIE, r"(?i)firebaseauth", 1.0, None)
    ]
