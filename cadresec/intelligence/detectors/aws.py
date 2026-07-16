from cadresec.intelligence.detectors.base import BaseDetector
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType

class AWSDetector(BaseDetector):
    name = "Amazon Web Services (AWS)"
    category = TechnologyCategory.CLOUD
    rules = [
        (EvidenceType.HEADER, r"(?i)x-amz-|x-amzn-", 0.95, None)
    ]
