import re
from typing import Optional, List, Tuple
from cadresec.intelligence.evidence import Evidence
from cadresec.intelligence.models import TechnologyProfile
from cadresec.intelligence.enums import TechnologyCategory, EvidenceType


class BaseDetector:
    name: str = ""
    category: TechnologyCategory = TechnologyCategory.SERVER
    # Format: [(evidence_type, regex_pattern, confidence, version_regex)]
    rules: List[Tuple[EvidenceType, str, float, Optional[str]]] = []

    def match(self, evidence: Evidence) -> Optional[TechnologyProfile]:
        """Evaluates a piece of evidence.
        
        Returns a TechnologyProfile if matched, otherwise None.
        """
        for ev_type, pattern, confidence, ver_pattern in self.rules:
            # Case-insensitive comparison of evidence category
            if evidence.category.lower() == ev_type.value.lower():
                match = re.search(pattern, evidence.value)
                if match:
                    version = None
                    if ver_pattern:
                        ver_match = re.search(ver_pattern, evidence.value)
                        if ver_match and ver_match.groups():
                            version = ver_match.group(1)
                    elif len(match.groups()) > 0 and match.group(1):
                        version = match.group(1)

                    desc = f"Matched {evidence.source} evidence '{evidence.value}' (confidence: {confidence:.2f}) from {evidence.originating_tool}"

                    return TechnologyProfile(
                        name=self.name,
                        technology=self.name,
                        category=self.category,
                        version=version,
                        confidence=confidence,
                        evidence=[desc]
                    )
        return None
