# Deploy Sentinel Audit on an always-on VPS

This deployment runs the existing Python backend and SQLite database in one container and places Caddy in front of it for HTTPS. The Android app connects to the public HTTPS origin; the backend does not depend on your laptop being on.

## 1. Prepare the VPS and DNS

Use a Linux VPS with Docker Engine and the Docker Compose plugin. Create a DNS `A` record for a hostname such as `sentinel.example.com` that points to the VPS. Add an `AAAA` record only if the VPS has working public IPv6. Allow inbound TCP 80 and 443 (and optionally UDP 443) in the VPS firewall/security group; restrict SSH to your own admin IP. Do not expose port 8080 publicly.

## 2. Copy the project and configure secrets

Copy/clone this repository to the VPS. From the repository root:

```sh
cp .env.example .env
```

Edit `.env` on the VPS. Set at least:

```dotenv
SENTINEL_DOMAIN=sentinel.example.com
AUDIT_SECRET=PASTE_A_UNIQUE_RANDOM_SECRET_HERE
AUDIT_REQUIRE_SCANNER_AGENT=1
```

Generate the secret on the VPS with `openssl rand -base64 48`. Keep the value private and stable across restarts; back it up securely. Do not commit `.env`. Add optional `NVD_API_KEY` and SMTP settings there if you use those services. Leave `AUDIT_API_URL` and `AUDIT_CORS_ORIGIN` unset: the app and API use the same HTTPS origin and do not need permissive CORS.

Compose sets `AUDIT_HOST=0.0.0.0` inside the private container network, `AUDIT_PORT=8080`, `AUDIT_DB=/data/audit.db`, secure cookies, and trusted proxy headers. The backend port is not published on the VPS; only Caddy can reach it on the private Docker network. Caddy supplies the client IP header used for audit and rate limiting. The SQLite file lives in the persistent `sentinel-data` volume. Caddy obtains and renews the HTTPS certificate after DNS resolves and ports 80/443 are reachable.

## 3. Start and initialize

```sh
docker compose config -q
docker compose up --build -d
docker compose ps
docker compose logs -f sentinel-audit caddy
```

Create the first administrator interactively:

```sh
docker compose exec sentinel-audit python -m security_audit --create-admin
```

The container applies SQLite schema migrations on startup and preserves the mounted database across image rebuilds. Do not run multiple backend replicas against the same SQLite file. Back up the database and Caddy's `caddy-data` volume.

## 4. Verify from the server and phone

From the VPS, confirm both endpoints return HTTP 200:

```sh
curl -fsS https://sentinel.example.com/healthz
curl -fsS https://sentinel.example.com/readyz
```

On the Android app, tap **Server** in the top bar and enter:

```text
https://sentinel.example.com/
```

Tap **Connect**, then sign in with the existing Sentinel account. Android saves this URL in app preferences. No Android Studio source change or APK rebuild is required just to change servers; if the app is reinstalled or its data is cleared, enter the URL again.

## Network scanner placement and limits

The container includes Nmap and receives only the `NET_RAW` Linux capability needed for packet-based Nmap checks; it drops all other Linux capabilities. Cloud deployment defaults `AUDIT_REQUIRE_SCANNER_AGENT=1`, so private network jobs are dispatched only to an online agent enrolled in the same organization. Do not expose Nmap or port 8080 directly to the internet.

### Enroll an organization scanner agent

1. Sign in as the main administrator or that organization’s administrator and open **Assessments → Private scanner agents**.
2. Create an agent name and copy the one-time token. It cannot be retrieved later; revoke and re-enroll if it is lost or exposed.
3. On an always-on computer connected to that organization’s LAN, install Python and Nmap and obtain the Sentinel source package. The agent initiates outbound HTTPS requests and opens no inbound port.
4. Install the project’s Python dependencies (`python -m pip install -r requirements.txt`), install Nmap, then in PowerShell from the repository root set the token and server URL and start the agent:

```powershell
$env:PYTHONPATH = "$PWD\security_audit"
$env:SENTINEL_AGENT_TOKEN = 'PASTE_ONE_TIME_TOKEN'
$env:SENTINEL_SERVER_URL = 'https://sentinel.example.com'
python -m security_audit.agent
```

5. Leave that process running. The UI accepts a private IPv4 scope only when an agent from the same organization checked in during the last two minutes. The agent accepts private IPv4 scopes up to `/24`, runs Sentinel’s fixed read-only scanner, and posts results to its assigned job. It does not accept shell commands or broaden scope. Revoke the agent from the same UI to invalidate its token and cancel active jobs.

Use HTTPS in production. The server stores only a hash of the one-time token; provide the token to the scanner through a protected environment variable. Nmap must be installed locally and available through PATH or `NMAP_PATH`. Local-system assessment still runs on the Sentinel server host; on a VPS it assesses the VPS, not the agent computer or Android phone.

Scan jobs run independently of the Android/browser connection. A VPS/container restart stops in-flight scans; Sentinel records interrupted jobs as failed so they can be reviewed and retried. SQLite and in-process scan workers make this a single-instance deployment, not a horizontally scaled/high-availability service.

## Server interface note

The current application uses `ThreadingHTTPServer` and is not a WSGI/ASGI application. The deployment keeps the existing routes and places that server on a private Docker network behind Caddy for TLS and internet-facing HTTP handling. Switching to Gunicorn/Waitress/Uvicorn directly would require an HTTP/WSGI adapter or a route-layer migration; neither is required for this single-instance container setup.
