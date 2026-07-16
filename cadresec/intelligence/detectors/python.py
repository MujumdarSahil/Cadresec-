from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class PythonDetector(BaseDetector):
    name = "Python"
    category = TechnologyCategory.LANGUAGE
    rules = [
        (EvidenceType.HEADER, r"(?i)server:\s*(?:gunicorn|uwsgi)", 0.8, None)
    ]
