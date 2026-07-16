from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class NextAuthDetector(BaseDetector):
    name = "NextAuth.js"
    category = TechnologyCategory.AUTH
    rules = [
        (EvidenceType.COOKIE, r"(?i)next-auth\.session-token|__Secure-next-auth\.session-token", 1.0, None)
    ]
