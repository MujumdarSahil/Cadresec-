from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class Auth0Detector(BaseDetector):
    name = "Auth0"
    category = TechnologyCategory.AUTH
    rules = [
        (EvidenceType.COOKIE, r"(?i)auth0", 1.0, None)
    ]
