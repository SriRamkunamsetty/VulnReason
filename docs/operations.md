# Operational Runbook & Incident Response

## 1. Daily Threat Intelligence Synchronization
The intelligence worker polls upstream data feeds according to the following schedule:
- **CISA KEV Feed**: Daily at 02:00 UTC (conditional HTTP request with ETag).
- **FIRST EPSS API**: Daily at 06:00 UTC.
- **NVD v2 API**: Hourly backoff batch sync.

To trigger an emergency manual sync:
```bash
curl -X POST http://localhost:8000/api/v1/intelligence/sync -H "Authorization: Bearer <TOKEN>"
```

---

## 2. Database Backup & Restore

### Automated Nightly Backup
```bash
pg_dump -U vulnreason -d vulnreason -Fc -f /backup/vulnreason_$(date +%Y%m%d).dump
```

### Point-in-Time Restore
```bash
pg_restore -U vulnreason -d vulnreason --clean --if-exists /backup/vulnreason_YYYYMMDD.dump
```

---

## 3. Incident Response: Remediation Gate Audit
If an auditor requires proof that findings were not arbitrarily suppressed:
1. Query `audit_events` table for `action = 'REMEDIATION_STATUS_UPDATED'`.
2. Inspect `remediation_evidence` table matching `remediation_task_id`.
3. Verify the cryptographic SHA-256 hash against the original scanner rescan log.
