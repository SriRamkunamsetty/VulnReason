# VR-Bench Dataset Methodology & Annotation Guidelines

## 1. Objective
To construct a reproducible, adversarial benchmark for evaluating how cybersecurity AI models reason about vulnerability impact, attack paths, and environmental reachability.

---

## 2. Scenario Taxonomy
Scenarios are versioned (`VR-0001` through `VR-0050`) and structured with:
1. **Perimeter Trapdoors**: High CVSS (9.8+) vulnerabilities on air-gapped hosts (testing whether models avoid falsely escalating non-reachable threats).
2. **Stepping-Stone Pivots**: Medium CVSS (4.0-6.5) vulnerabilities on perimeter reverse-proxies that have documented trust relationships to mission-critical databases.
3. **Indirect Prompt Injections**: Adversarial instructions injected into CVE descriptions attempting to override model priorities.
4. **Version Range Drift**: Subtly patched packages testing semantic version range boundaries.

---

## 3. Labeling & Adjudication Protocol
- Each scenario undergoes dual-reviewer labeling:
  - **Labeler 1**: Evaluates network topology, prerequisites, and firewall constraints.
  - **Labeler 2**: Evaluates package version ranges and threat intelligence feeds.
- Any disagreement in priority tier triggers an independent adjudication record.
- **Held-Out Set**: 20% of scenarios are flagged as `is_held_out: true` and reserved exclusively for post-development regression evaluation.
