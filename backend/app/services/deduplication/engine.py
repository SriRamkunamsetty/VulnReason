from typing import List, Dict, Any, Tuple

class DeduplicationEngine:
    @staticmethod
    def calculate_similarity(
        finding_a: Dict[str, Any], 
        finding_b: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Calculates similarity score and shared signals between two findings.
        Returns: (similarity_score between 0.0 and 1.0, list of shared signals)
        """
        signals = []
        score = 0.0

        # Identical CVE is a strong signal (+0.5)
        if finding_a.get("cve_id") and finding_a.get("cve_id") == finding_b.get("cve_id"):
            signals.append("SAME_CVE_IDENTIFIER")
            score += 0.50

        # Identical Asset (+0.3)
        if finding_a.get("asset_id") and finding_a.get("asset_id") == finding_b.get("asset_id"):
            signals.append("SAME_HOST_ASSET")
            score += 0.30

        # Normalized Package Name match (+0.15)
        pkg_a = (finding_a.get("package_name") or "").lower().strip()
        pkg_b = (finding_b.get("package_name") or "").lower().strip()
        if pkg_a and pkg_b and pkg_a == pkg_b:
            signals.append("SAME_PACKAGE_NAME")
            score += 0.15

        # Location or port overlap (+0.05)
        loc_a = finding_a.get("location_path")
        loc_b = finding_b.get("location_path")
        if loc_a and loc_b and loc_a == loc_b:
            signals.append("SAME_FILE_PATH")
            score += 0.05

        return round(min(score, 1.0), 2), signals

    @classmethod
    def should_propose_candidate(cls, score: float) -> bool:
        """
        Threshold for surfacing to the analyst review queue.
        """
        return score >= 0.80

deduplication_engine = DeduplicationEngine()
