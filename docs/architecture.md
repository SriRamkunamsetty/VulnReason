# VulnReason System Architecture & Technical Specification

## 1. Architectural Philosophy
VulnReason separates deterministic security proof from probabilistic AI inference:
> **"An explanation is not evidence, and a plausible attack path is not a confirmed attack path."**

The platform operates as a modular monolith with asynchronous workers, backed by PostgreSQL as the authoritative relational store and NetworkX for in-memory graph traversal.

---

## 2. Component Blueprint

```
+-----------------------------------------------------------------------------------+
|                                  React 18 UI                                      |
|   - SOC Dashboard           - Contextual Triage Drawer   - Attack Graph Explorer  |
|   - Counterfactual Sim      - VR-Bench Scorecard         - Verification Gates     |
+------------------------------------------+----------------------------------------+
                                           | HTTP / REST (OpenAPI 3.1)
+------------------------------------------v----------------------------------------+
|                               FastAPI Security Gateway                            |
|   - Argon2id & JWT Auth     - Tenant Context Middleware  - X-Correlation-ID Audit |
|   - Strict Pydantic v2      - Rate Limiting              - Role-Based Access      |
+-------------------+----------------------+--------------------+-------------------+
                    |                      |                    |
+-------------------v---+  +---------------v---+  +-------------v----+  +-----------v---+
| Ingestion & Intel     |  | Deterministic     |  | NetworkX Graph   |  | Structured AI |
| - CycloneDX 1.5 SBOM  |  | Contextual Policy |  | Traversal Engine |  | Reasoning &   |
| - SARIF JSON & CSV    |  | - KEV Alert Rules |  | - Bounded Search |  | Citation      |
| - NVD v2 / EPSS API   |  | - EPSS Percentile |  | - Cut-Set Diff   |  | Auditor       |
| - SemVer Solver       |  | - Exposure Matrix |  | - Sim Sandbox    |  | (0.0% UCR)    |
+-----------------------+  +-------------------+  +------------------+  +---------------+
                    |                      |                    |                   |
+-------------------v----------------------v--------------------v-------------------v---+
|                              PostgreSQL 16 Relational Store                           |
|       28+ Normalized Tables: Assets, Findings, Edges, Evidence, Audits, Benchmarks     |
+---------------------------------------------------------------------------------------+
```

---

## 3. The Multi-Signal Risk Matrix (Rejecting CVSS x EPSS)
VulnReason rejects the mathematical anti-pattern of multiplying ordinal CVSS scores with EPSS probabilities. Instead, it enforces a non-multiplicative multi-signal matrix:

1. **Rule P0-1**: $KEV = \text{True} \land (\text{Exposure} \in \{\text{INTERNET}, \text{DMZ}\} \lor \text{Path} = \text{Reachable}) \implies \mathbf{P0\_URGENT}$ (24-48h SLA).
2. **Rule P1-1**: $KEV = \text{True} \land \text{Exposure} = \text{INTERNAL} \implies \mathbf{P1\_HIGH}$ (7d SLA).
3. **Rule P1-2**: $EPSS \ge 0.90 \land \text{Exposure} = \text{INTERNET} \land \text{Criticality} \in \{\text{CRITICAL}, \text{HIGH}\} \implies \mathbf{P0\_URGENT}$ if $CVSS \ge 9.0$ else $\mathbf{P1\_HIGH}$.
4. **Rule P2-1**: $CVSS \ge 9.0 \land \text{Exposure} = \text{RESTRICTED\_ISOLATED} \land Path = \text{Unreachable} \implies \mathbf{P2\_MEDIUM}$.
5. **Rule P3-1**: $\text{Applicability} = \text{NOT\_APPLICABLE} \implies \mathbf{P3\_LOW}$.

---

## 4. Attack Graph & Counterfactual Simulation
- Directed multigraph constructed per tenant from relational assets and network permissions.
- Traversal bounded by `max_depth = 5` and cycle elimination to guarantee sub-millisecond path resolution on 50,000-edge graphs.
- **Counterfactual Engine**: In-memory graph cloning. Simulates severing network edges or patching vulnerabilities to calculate the exact differential of severed critical paths.

---

## 5. Indirect Prompt Injection Sandboxing & Citation Audit
- External untrusted scanner findings and descriptions are wrapped into escaped XML boundaries (`<finding_evidence>`, `<asset_evidence>`).
- Structured LLM outputs must conform to Pydantic schemas.
- `DeterministicCitationAuditor` validates that every evidence ID cited by the AI actually exists in the database. Unsupported claims are flagged and rejected with a 0.0% tolerance rate.
