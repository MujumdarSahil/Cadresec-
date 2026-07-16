from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class WordPressDetector(BaseDetector):
    name = "WordPress"
    category = TechnologyCategory.CMS
    rules = [
        (EvidenceType.HTML, r"(?i)/wp-content/|/wp-includes/|wp-submit", 0.95, None),
        (EvidenceType.META, r"(?i)wordpress\s*([\d\.]+)", 1.0, r"(?i)wordpress\s*([\d\.]+)"),
        (EvidenceType.COOKIE, r"(?i)wordpress_logged_in_|wp-settings-", 1.0, None)
    ]
