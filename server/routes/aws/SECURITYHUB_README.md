# AWS Security Hub Webhook Integration

This document outlines the architecture, flow, and schema of the strictly verified Amazon EventBridge webhook integration for AWS Security Hub.

## High-Level Architecture
Aurora ingests security findings from AWS via an inbound Webhook (HTTP POST) triggered by an Amazon EventBridge API Destination. 
The integration utilizes a "Human-in-the-Loop" triage system, strictly ensuring zero autonomous remediation.

1. **Amazon EventBridge** triggers a POST to `/api/v1/aws/securityhub/webhook/<org_id>`
2. **Flask Route** validates the payload and the securely-matched API Key.
3. **Prometheus Metrics** measure latency, successful ingestions, and failures.
4. **Celery Worker** extracts the finding asynchronously.
5. **AI triage agent** constructs a summary and recommended remediation flow.
6. **Postgres** securely UPSERTS the modified entity, ignoring noise or dupes.

---

## 1. Routing & Security (`securityhub_routes.py`)

**Path**: `POST /aws/securityhub/webhook/<org_id>`

### API Key Validation
The webhook is strictly isolated using `X-Api-Key` HTTP headers.
- **Why no `.env` keys?** To support Multi-Tenant architecture, Aurora parses the `<org_id>` URL parameter and executes a fast query against the Postgres `user_tokens` table.
- **Timing Attacks Prevented**: Validation natively uses Python's `hmac.compare_digest()` to completely protect against timing-based enumeration attacks.
- **Dev Bypass**: A development-only bypass exists `DEV_SECURITYHUB_API_KEY` but is thoroughly neutered in production via absolute checking against `FLASK_ENV == "development"`.

### Metrics Telemetry
We use `prometheus_client` to expose metric vectors:
- `aws_securityhub_events_received_total`: Increments immediately upon passing the Auth gate.
- `aws_securityhub_events_failed_total`: Categorized by internal logic failures (`missing_api_key`, `invalid_source`). 
- `aws_securityhub_processing_latency_seconds`: `Histogram` tracking the API's immediate JSON processing delays before asynchronous handoff.

---

## 2. Background Task Execution (`tasks.py`)

To prevent blocking the HTTP process, all payload mutation processing happens within `@shared_task def process_securityhub_finding()`.

### Fault Tolerance & Reliability
- **Retry Semantics**: Broad `exceptions` are caught, logged, and re-raised (`raise`). Celery uses this exit status to gracefully retry the payload.
- **Type-Safety Assurance**: Malformed AWS JSON schemas where `.findings` iterates primitive strings instead of proper `dict` payloads will gracefully loop `continue` avoiding application tier `AttributeErrors`.

### Agentic Triage (Human in the loop)
We utilize `_generate_ai_triage()` to analyze the raw `finding`.
- **Purpose**: Generates contextually aware `summary`, `risk_level`, and `suggested_fix`.
- **Limit**: Strictly prevents autonomous AWS actions.

---

## 3. Database Schema & Idempotency (`utils/db/db_utils.py`)

A new table `aws_security_findings` enforces uniqueness against noisy Amazon pipelines.

```sql
CREATE TABLE IF NOT EXISTS aws_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id VARCHAR(255) NOT NULL,
    finding_id VARCHAR(255) NOT NULL,
    source VARCHAR(200),
    title TEXT,
    severity_label VARCHAR(100),
    payload JSONB,
    ai_summary TEXT,
    ai_risk_level VARCHAR(100),
    ai_suggested_fix TEXT,
    remediation_approved BOOLEAN DEFAULT FALSE,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, finding_id)
);
```

### Idempotency Behavior
`tasks.py` executes an UPSERT utilizing:
```sql
ON CONFLICT (org_id, finding_id) DO UPDATE SET
    title = EXCLUDED.title,
    severity_label = EXCLUDED.severity_label,
    payload = EXCLUDED.payload,
    updated_at = NOW()
```
If AWS pushes state updates (e.g. GuardDuty severity changed from MEDIUM to HIGH), the exact row mutates `updated_at` securely without triggering massive `INSERT` duplication.

---

## 4. Dependencies
Added robust dependency management for the newly integrated Route metrics directly inside `server/requirements.txt`:
```ini
prometheus-client>=0.20.0
```
This resolves internal virtual environment tracking deficits and ensures the entire Python runtime starts cleanly on Kubernetes/Docker initializations.
