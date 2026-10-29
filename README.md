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

## Encrypted file vault

The dashboard's **Encrypted file vault** encrypts files in the browser with
AES-256-GCM using a password that is never sent to the server. The API stores
only the encrypted bytes, encryption metadata, and hashes. SQLite persists file
metadata and a hash-linked audit trail under `data/`; set `CLOUD_DATA_DIR` to
choose another data location.

The API provides:

- `POST /files` - store a browser-encrypted file payload
- `GET /files` - list stored file metadata
- `GET /files/<id>/download` - download encrypted bytes for browser decryption
- `POST /files/<id>/verify` - verify the stored ciphertext against its recorded hash

## Deploy on Render

This repository includes a `render.yaml` Blueprint configuration. In Render,
choose **New > Blueprint**, connect the GitHub repository, and select the
repository's `render.yaml` file. Render will install the dependencies and start
the Flask app with Gunicorn. The deployed health endpoint is `/health`.
