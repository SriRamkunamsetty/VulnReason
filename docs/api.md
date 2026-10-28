# VulnReason API Reference (`/api/v1`)

All endpoints require authentication (or fallback to the verified tenant context in development). Responses return standard JSON with RFC 7807 problem details for errors.

---

## 1. Authentication (`/api/v1/auth`)
- `POST /api/v1/auth/login`: Authenticate with email/password. Returns short-lived JWT access token and sets secure refresh cookie.
- `POST /api/v1/auth/register`: Provision a new user account.

---

## 2. Findings & Triage (`/api/v1/findings`)
- `GET /api/v1/findings`: Query normalized findings (filters: `priority`, `status`, `applicability`, `cve_id`).
- `GET /api/v1/findings/{id}`: Full finding detail with observation history and asset context.
- `PATCH /api/v1/findings/{id}/applicability`: Human override of applicability with mandatory rationale.
- `GET /api/v1/findings/{id}/report`: Downloadable Markdown/text security assessment report.
- `GET /api/v1/findings/deduplication/candidates`: Pending duplicate pairs with similarity scores.
- `POST /api/v1/findings/deduplication/review/{id}`: Accept (`MERGED`) or reject duplicate candidate.

---

## 3. Attack Graph & Simulation (`/api/v1/graph`)
- `GET /api/v1/graph/paths`: Bounded attack path traversal targeting mission-critical assets.
- `POST /api/v1/graph/simulate`: Counterfactual remediation simulation (severed edges and remediated CVEs).

---

## 4. AI Structured Reasoning (`/api/v1/reasoning`)
- `POST /api/v1/reasoning/assess/{finding_id}`: Generates structured narrative and runs the deterministic citation audit.

---

## 5. VR-Bench Adversarial Benchmark (`/api/v1/evaluation`)
- `GET /api/v1/evaluation/scenarios`: Returns benchmark test scenarios.
- `POST /api/v1/evaluation/run`: Executes 5-baseline evaluation run and returns comparative scorecard.

---

## 6. Remediation & Verification (`/api/v1/remediation`)
- `GET /api/v1/remediation/tasks`: Active remediation tasks with SLA due dates.
- `POST /api/v1/remediation/tasks`: Assign finding to team with SLA.
- `PATCH /api/v1/remediation/tasks/{id}`: Update task status. Transitioning to `RESOLVED` strictly requires `verification_type` and `evidence_proof`.

---

## 7. Ingestion (`/api/v1/imports`)
- `POST /api/v1/imports`: Multipart upload accepting CycloneDX 1.5 JSON, SARIF, or CSV reports.
