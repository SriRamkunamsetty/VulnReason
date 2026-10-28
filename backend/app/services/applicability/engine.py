import re
from typing import Tuple, Optional

class ApplicabilityEngine:
    @staticmethod
    def parse_version_tuple(v_str: str) -> Optional[Tuple[int, ...]]:
        """
        Extracts numeric sequence from version string (e.g., '2.14.1' -> (2, 14, 1)).
        """
        if not v_str:
            return None
        # Clean string from leading 'v' or suffixes like '-beta'
        cleaned = re.sub(r'^[vV]', '', v_str.strip())
        cleaned = cleaned.split('-')[0].split('+')[0]
        parts = []
        for p in cleaned.split('.'):
            if p.isdigit():
                parts.append(int(p))
            else:
                digits = re.findall(r'\d+', p)
                if digits:
                    parts.append(int(digits[0]))
                else:
                    parts.append(0)
        return tuple(parts) if parts else None

    @classmethod
    def evaluate_applicability(
        cls, 
        installed_version: Optional[str], 
        fixed_version: Optional[str],
        affected_range: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Determines applicability status and rationale.
        States: CONFIRMED_APPLICABLE, NOT_APPLICABLE, INSUFFICIENT_EVIDENCE
        """
        if not installed_version:
            return (
                "INSUFFICIENT_EVIDENCE",
                "Asset software component is detected, but installed version string is absent or unverifiable."
            )

        installed_tuple = cls.parse_version_tuple(installed_version)
        if not installed_tuple:
            return (
                "INSUFFICIENT_EVIDENCE",
                f"Installed version '{installed_version}' could not be parsed into a comparable semantic structure."
            )

        if fixed_version:
            fixed_tuple = cls.parse_version_tuple(fixed_version)
            if fixed_tuple:
                # Compare tuples with padding
                max_len = max(len(installed_tuple), len(fixed_tuple))
                v_inst = installed_tuple + (0,) * (max_len - len(installed_tuple))
                v_fix = fixed_tuple + (0,) * (max_len - len(fixed_tuple))

                if v_inst < v_fix:
                    return (
                        "CONFIRMED_APPLICABLE",
                        f"Installed version {installed_version} is strictly less than vendor fixed release {fixed_version}."
                    )
                else:
                    return (
                        "NOT_APPLICABLE",
                        f"Installed version {installed_version} is at or above the fixed version {fixed_version}."
                    )

        # Fallback if no fixed version provided
        return (
            "LIKELY_APPLICABLE",
            f"Vulnerability report matches package identity with installed version {installed_version}, but fixed version threshold is unverified."
        )

applicability_engine = ApplicabilityEngine()
