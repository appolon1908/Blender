# Blender Standalone SaaS Baseline

This additive sidecar makes Blender independently callable without requiring Codestra Middleware, Kong, or Caddy. Blender remains the native 3D/render engine; the sidecar owns the API, tenant/job boundary, durable local ledger, and safe worker invocation.

Implemented now:
- FastAPI + OpenAPI (`/openapi.json`, `/docs`)
- `/healthz`, `/readyz`, `/v1/capabilities`
- tenant-scoped durable SQLite job ledger
- `Idempotency-Key` on job create/cancel
- bearer service authentication that fails closed outside development mode
- `render_frame` and `render_animation` jobs
- bounded input/output workspaces and `shell=False` engine execution
- worker timeout/result capture
- execution disabled by default
- loopback-only Docker Compose API
- focused CI tests

Standalone path:
`client -> Blender SaaS API -> durable job ledger -> native Blender worker -> artifact`

Integrated path:
`client -> Caddy -> Kong -> Middleware -> Blender connector -> Blender SaaS API`

The native Blender process must never be exposed directly through Caddy or Kong. Large media should move through object storage rather than through Middleware.

Local API:
```bash
python3 -m venv .venv-saas
. .venv-saas/bin/activate
pip install -r requirements-saas.txt
export CODESTRA_AUTH_MODE=development
uvicorn codestra_saas:app --host 127.0.0.1 --port 8080
```

Native worker (only on a host with Blender installed):
```bash
export CODESTRA_EXECUTION_ENABLED=true
export CODESTRA_INPUT_ROOT=/srv/blender/inputs
export CODESTRA_OUTPUT_ROOT=/srv/blender/outputs
python codestra_saas.py --worker
```

Production certification is not claimed. Next hardening: PostgreSQL, object storage, signed events/webhooks, quotas/metering, Keycloak/OIDC, OpenBao secrets, metrics/traces, artifact QC, and Middleware/Kong/Caddy contract certification.
