import json
import csv
import io
from typing import List, Dict, Any, Tuple

class IngestionParser:
    @staticmethod
    def parse_cyclonedx(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parses CycloneDX 1.5 SBOM JSON.
        Returns: (components, vulnerabilities)
        """
        data = json.loads(content)
        components = []
        for c in data.get("components", []):
            components.append({
                "name": c.get("name"),
                "version": c.get("version"),
                "purl": c.get("purl"),
                "type": c.get("type"),
                "cpe": c.get("cpe")
            })

        vulnerabilities = []
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("id")
            affects = v.get("affects", [])
            target_ref = affects[0].get("ref") if affects else None
            vulnerabilities.append({
                "cve_id": cve_id,
                "description": v.get("description"),
                "target_ref": target_ref,
                "ratings": v.get("ratings", [])
            })
        return components, vulnerabilities

    @staticmethod
    def parse_sarif(content: str) -> List[Dict[str, Any]]:
        """
        Parses SARIF JSON output.
        """
        data = json.loads(content)
        findings = []
        for run in data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "SARIF_SCANNER")
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "UNKNOWN_RULE")
                msg = result.get("message", {}).get("text", "")
                locations = result.get("locations", [])
                file_path = None
                if locations:
                    phys = locations[0].get("physicalLocation", {}).get("artifactLocation", {})
                    file_path = phys.get("uri")

                findings.append({
                    "scanner_name": tool_name,
                    "cve_id": rule_id if rule_id.startswith("CVE-") else f"CVE-UNKNOWN-{rule_id}",
                    "description": msg,
                    "location_path": file_path,
                    "raw_finding_id": result.get("correlationGuid") or rule_id
                })
        return findings

    @staticmethod
    def parse_csv(content: str) -> List[Dict[str, Any]]:
        """
        Parses standard CSV vulnerability exports.
        """
        f = io.StringIO(content.strip())
        reader = csv.DictReader(f)
        findings = []
        for row in reader:
            # Map standard keys
            cve = row.get("cve_id") or row.get("CVE") or row.get("cve") or "CVE-UNKNOWN"
            pkg = row.get("package_name") or row.get("Package") or row.get("component")
            ver = row.get("installed_version") or row.get("Version") or row.get("installed")
            host = row.get("hostname") or row.get("Host") or row.get("asset") or "default-host"
            sev = row.get("severity") or row.get("Severity") or "MEDIUM"

            findings.append({
                "cve_id": cve.strip(),
                "package_name": pkg.strip() if pkg else None,
                "installed_version": ver.strip() if ver else None,
                "hostname": host.strip(),
                "severity": sev.strip()
            })
        return findings

ingestion_parser = IngestionParser()
