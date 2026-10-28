from typing import Dict, Any, List, Tuple

class ContextualRiskEngine:
    POLICY_VERSION = "v1.2.0-deterministic"

    @classmethod
    def evaluate(cls, signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates risk priority using non-multiplicative multi-signal policy rules.
        """
        is_kev = bool(signals.get("is_cisa_kev", False))
        epss_p = float(signals.get("epss_percentile", 0.0))
        cvss = float(signals.get("cvss_score", 0.0))
        exposure = signals.get("asset_exposure", "INTERNAL")
        criticality = signals.get("asset_criticality", "MEDIUM")
        has_path = bool(signals.get("has_reachable_attack_path", False))
        has_control = bool(signals.get("has_compensating_control", False))
        applicability = signals.get("applicability", "CONFIRMED_APPLICABLE")

        applied_rules: List[str] = []
        reasoning: List[str] = []
        uncertainties: List[str] = []

        # If not applicable, immediately low priority
        if applicability == "NOT_APPLICABLE":
            applied_rules.append("RULE_VERIFIED_NOT_APPLICABLE")
            reasoning.append("Component installed version is not affected by this vulnerability.")
            return {
                "priority_tier": "P3_LOW",
                "policy_version": cls.POLICY_VERSION,
                "applied_rules": applied_rules,
                "reasoning_factors": reasoning,
                "uncertainties": uncertainties,
                "recommended_action": "Mark as verified non-applicable; verify on next component release."
            }

        # Check for exposure uncertainty
        if exposure == "UNKNOWN":
            uncertainties.append("Asset network exposure boundary is unverified.")

        # Rule 1: Active in-the-wild exploitation + Perimeter/Path = P0_URGENT
        if is_kev:
            applied_rules.append("RULE_CISA_KEV_ACTIVE_EXPLOIT")
            reasoning.append("Vulnerability is documented in CISA Known Exploited Vulnerabilities catalog.")
            if exposure in ["INTERNET_FACING", "DMZ"] or has_path:
                applied_rules.append("RULE_PERIMETER_REACHABLE_KEV")
                reasoning.append("Asset is perimeter-exposed or participates in an active reachable attack path.")
                return {
                    "priority_tier": "P0_URGENT",
                    "policy_version": cls.POLICY_VERSION,
                    "applied_rules": applied_rules,
                    "reasoning_factors": reasoning,
                    "uncertainties": uncertainties,
                    "recommended_action": "Execute immediate emergency mitigation or patching within 24-48 hours."
                }
            else:
                reasoning.append("Asset is internal, but KEV listing requires expedited triage.")
                return {
                    "priority_tier": "P1_HIGH",
                    "policy_version": cls.POLICY_VERSION,
                    "applied_rules": applied_rules,
                    "reasoning_factors": reasoning,
                    "uncertainties": uncertainties,
                    "recommended_action": "Schedule priority patching within 7 days; verify network segmentation."
                }

        # Rule 2: High EPSS (>90th percentile) on Exposed High-Value Asset
        if epss_p >= 0.90:
            applied_rules.append("RULE_HIGH_EPSS_EXPLOITATION_PROBABILITY")
            reasoning.append(f"Elevated 30-day exploitation likelihood: EPSS is at the {epss_p:.1%} percentile.")
            if exposure in ["INTERNET_FACING", "DMZ"] and criticality in ["MISSION_CRITICAL", "HIGH"]:
                applied_rules.append("RULE_EXPOSED_CRITICAL_ASSET")
                reasoning.append("Direct perimeter exposure on high-value asset.")
                return {
                    "priority_tier": "P0_URGENT" if cvss >= 9.0 else "P1_HIGH",
                    "policy_version": cls.POLICY_VERSION,
                    "applied_rules": applied_rules,
                    "reasoning_factors": reasoning,
                    "uncertainties": uncertainties,
                    "recommended_action": "Apply vendor remediation or restrict perimeter ingress immediately."
                }
            return {
                "priority_tier": "P1_HIGH",
                "policy_version": cls.POLICY_VERSION,
                "applied_rules": applied_rules,
                "reasoning_factors": reasoning,
                "uncertainties": uncertainties,
                "recommended_action": "Prioritize remediation in next scheduled maintenance cycle."
            }

        # Rule 3: Confirmed Chained Attack Path to Mission-Critical Asset
        if has_path and criticality in ["MISSION_CRITICAL", "HIGH"]:
            applied_rules.append("RULE_CHAINED_ATTACK_PATH_TO_CROWN_JEWEL")
            reasoning.append("Weakness enables lateral movement toward a mission-critical asset.")
            if not has_control:
                reasoning.append("No active compensating control detected to sever the lateral route.")
                return {
                    "priority_tier": "P1_HIGH",
                    "policy_version": cls.POLICY_VERSION,
                    "applied_rules": applied_rules,
                    "reasoning_factors": reasoning,
                    "uncertainties": uncertainties,
                    "recommended_action": "Remediate host vulnerability or apply micro-segmentation rule."
                }
            else:
                reasoning.append("Compensating control partially mitigates direct lateral exploitability.")
                return {
                    "priority_tier": "P2_MEDIUM",
                    "policy_version": cls.POLICY_VERSION,
                    "applied_rules": applied_rules,
                    "reasoning_factors": reasoning,
                    "uncertainties": uncertainties,
                    "recommended_action": "Maintain compensating control and verify control health."
                }

        # Rule 4: Isolated host with high CVSS
        if cvss >= 9.0 and exposure == "RESTRICTED_ISOLATED" and not has_path:
            applied_rules.append("RULE_CRITICAL_CVSS_ISOLATED_BLAST_RADIUS")
            reasoning.append("High intrinsic CVSS score, but asset is strictly isolated with no known lateral pivot.")
            return {
                "priority_tier": "P2_MEDIUM",
                "policy_version": cls.POLICY_VERSION,
                "applied_rules": applied_rules,
                "reasoning_factors": reasoning,
                "uncertainties": uncertainties,
                "recommended_action": "Remediate during standard 30-day maintenance window."
            }

        # Rule 5: Standard Base Severity
        if cvss >= 7.0 or epss_p >= 0.50:
            applied_rules.append("RULE_STANDARD_MEDIUM_SEVERITY")
            reasoning.append("Moderate threat signal without confirmed active lateral threat.")
            return {
                "priority_tier": "P2_MEDIUM",
                "policy_version": cls.POLICY_VERSION,
                "applied_rules": applied_rules,
                "reasoning_factors": reasoning,
                "uncertainties": uncertainties,
                "recommended_action": "Remediate within standard 30-day SLA."
            }

        applied_rules.append("RULE_LOW_RISK_BASELINE")
        reasoning.append("Low exploitation likelihood and low intrinsic severity.")
        return {
            "priority_tier": "P3_LOW",
            "policy_version": cls.POLICY_VERSION,
            "applied_rules": applied_rules,
            "reasoning_factors": reasoning,
            "uncertainties": uncertainties,
            "recommended_action": "Review on normal 90-day cycle or during next dependency update."
        }

risk_engine = ContextualRiskEngine()
