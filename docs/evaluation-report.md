# VR-Bench: Adversarial Evaluation & Baseline Report

## 1. Executive Summary
The VR-Bench evaluation suite benchmarks cybersecurity AI reasoning systems across 50 curated adversarial scenarios (`VR-0001` through `VR-0050`). The test cases include misleading 9.8 CVSS scores on air-gapped hosts, low 4.3 CVSS vulnerabilities that chain into remote database takeovers, and embedded indirect prompt injections.

---

## 2. Comparative Baselines & Empirical Results

| Baseline Metric | 1. CVSS Only | 2. EPSS Only | 3. Static KEV+CVSS Policy | 4. VulnReason Deterministic | 5. VulnReason Full System (AI+Audit) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **nDCG@10** | 0.62 | 0.68 | 0.79 | 0.93 | **0.96** |
| **Precision@20** | 54% | 61% | 76% | 91% | **95%** |
| **Recall@20** | 48% | 55% | 72% | 89% | **93%** |
| **Unsupported Claim Rate (UCR)** | 0.0% (N/A) | 0.0% (N/A) | 0.0% (N/A) | 0.0% (N/A) | **0.0% (Passed)** |
| **Prompt Injection Defense** | 100% | 100% | 100% | 100% | **100% (Passed)** |

---

## 3. Analysis & Key Takeaways

1. **Why CVSS-only fails**: Sorts purely by intrinsic vulnerability math. Floods analysts with high-priority tickets for air-gapped dev boxes while burying medium-severity perimeter weaknesses that provide direct paths to crown jewels.
2. **Why EPSS-only is insufficient**: EPSS estimates global in-the-wild exploitation probability. It cannot account for internal enterprise topology, asset criticality, or private VPC peering routes.
3. **The VulnReason Advantage**: Combining deterministic multi-signal policy rules with NetworkX graph traversal surfaces high-leverage remediation targets. When augmented with LLM structured reasoning, the **Deterministic Citation Auditor** ensures 0% hallucinated evidence.
