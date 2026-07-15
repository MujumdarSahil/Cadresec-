from typing import List, Dict, Any
from cadresec.intelligence.evidence import Evidence
from cadresec.intelligence.models import TechnologyProfile
from cadresec.intelligence.registry import DetectorRegistry


class FingerprintEngine:
    def __init__(self):
        # Dynamically discover and instantiate all available detectors
        detector_classes = DetectorRegistry.load_detectors()
        self.detectors = [cls() for cls in detector_classes]

    def analyze(self, evidence_list: List[Evidence]) -> List[TechnologyProfile]:
        """Consumes a list of Evidence objects, runs all registered detectors,
        
        aggregates the results, and returns a sorted list of matched TechnologyProfiles.
        """
        # Map of technology name -> list of matched profiles for that technology
        matches: Dict[str, List[TechnologyProfile]] = {}

        # 1. Evaluate every piece of evidence against every detector
        for evidence in evidence_list:
            for detector in self.detectors:
                try:
                    profile = detector.match(evidence)
                    if profile:
                        if profile.name not in matches:
                            matches[profile.name] = []
                        matches[profile.name].append(profile)
                except Exception:
                    # Robust execution: don't let one failing detector crash the engine
                    pass

        # 2. Aggregate matched profiles per technology
        aggregated_profiles: List[TechnologyProfile] = []
        for tech_name, profiles in matches.items():
            # Extract category (they should be identical for the same detector, so take the first)
            category = profiles[0].category

            # Find the best version string (from the match with the highest confidence)
            sorted_by_conf = sorted(profiles, key=lambda x: x.confidence, reverse=True)
            version = next((p.version for p in sorted_by_conf if p.version), None)

            # Calculate accumulated confidence using a Noisy-OR model
            # Formula: 1.0 - product(1.0 - c_i)
            # This mathematically models the accumulation of evidence.
            combined_product = 1.0
            for p in profiles:
                combined_product *= (1.0 - p.confidence)
            
            combined_confidence = round(1.0 - combined_product, 4)

            # Merge all evidence descriptions, preserving order and uniqueness
            merged_evidence: List[str] = []
            seen_evidence = set()
            for p in profiles:
                for desc in p.evidence:
                    if desc not in seen_evidence:
                        seen_evidence.add(desc)
                        merged_evidence.append(desc)

            # Merge all metadata dictionaries
            merged_metadata: Dict[str, Any] = {}
            for p in profiles:
                if p.metadata:
                    merged_metadata.update(p.metadata)

            # Select first available recommendation
            recommendation = next((p.recommendation for p in profiles if p.recommendation), None)

            aggregated_profiles.append(
                TechnologyProfile(
                    name=tech_name,
                    technology=tech_name,
                    category=category,
                    version=version,
                    confidence=combined_confidence,
                    evidence=merged_evidence,
                    recommendation=recommendation,
                    metadata=merged_metadata
                )
            )

        # 3. Sort by confidence descending, then by name alphabetically for consistency
        return sorted(aggregated_profiles, key=lambda p: (-p.confidence, p.name))
