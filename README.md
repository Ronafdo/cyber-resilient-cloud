# Cyber-Resilient Cloud Infrastructure

This workspace scaffolds a college capstone project for a defense-in-depth cloud security system.

## Structure

- cyber_resilient_cloud/shield/ - DDoS detection and mitigation components
- cyber_resilient_cloud/vault/ - client-side encryption engine
- cyber_resilient_cloud/merkle/ - Merkle tree integrity engine
- cyber_resilient_cloud/blockchain/ - append-only audit log
- cyber_resilient_cloud/api/ - Flask API layer
- cyber_resilient_cloud/dashboard/ - monitoring dashboard assets
- tests/ - unit tests for the core modules

## Run locally

```powershell
.\.venv\Scripts\python.exe run.py
```

Open <http://127.0.0.1:5000/dashboard>.

The traffic shield accepts validated JSON events at `POST /shield/ingest`.
The source IP is taken from the client connection, and sources exceeding the
sliding-window threshold are blocked. Configure the defaults with
`SHIELD_RATE_LIMIT` and `SHIELD_WINDOW_SECONDS`.

## Deploy on Render

This repository includes a `render.yaml` Blueprint configuration. In Render,
choose **New > Blueprint**, connect the GitHub repository, and select the
repository's `render.yaml` file. Render will install the dependencies and start
the Flask app with Gunicorn. The deployed health endpoint is `/health`.
