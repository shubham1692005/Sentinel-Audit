# Sentinel Audit

Sentinel Audit is a self-hosted IT security audit and cyber risk assessment platform backed by SQLite. Its desktop browser client and Android WebView client share the same server-side database and authenticated API. Python 3.11+ and the packages in `requirements.txt` are required.

## Run

Requires Python 3.11 or newer. Install dependencies once, configure `.env`, then from this directory:

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
$env:PYTHONPATH = "$PWD\security_audit"
# Generate a secret and put it in AUDIT_SECRET in .env. Configure SMTP and Turnstile for account email flows.
python -m security_audit --init
python -m security_audit.create_admin
python -m security_audit
```

The first-admin command securely asks for full name, username, email, and a confirmed password. Existing users and assessment data are preserved by the schema migration. Then open http://localhost:8080. Environment variables override `.env`. Set `AUDIT_SECRET` to at least 32 random characters (prefer a 48-byte cryptographic random value) and keep it stable across restarts; it signs sessions and encrypts TOTP secrets. The example environment intentionally leaves it blank. The server refuses non-loopback binding with a blank, short, or placeholder secret. Use HTTPS through a trusted reverse proxy and set `AUDIT_COOKIE_SECURE=1` when TLS terminates in front of the service.

### Authentication and accounts

- Argon2id password hashes; existing PBKDF2 accounts remain readable and are upgraded after a successful login.
- Self-registration requires a 6–256 character password; it does not require a CAPTCHA or verification email. The email address is not mailbox-verified for self-registered accounts. Password-reset email, administrator invitations, and legacy verification resend require a reachable SMTP provider. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, and the provider's SMTP credentials in the local `.env`. Set `AUDIT_PUBLIC_URL` to the address users can open from their device (for example, the laptop LAN URL) so reset/invitation links work remotely.
- Cloudflare Turnstile is used for repeated login failures when configured and for legacy verification-email resend. Set `CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY`; the backend verifies tokens with Cloudflare. Login attempts and registration remain rate-limited. Password recovery still requires SMTP because a reset token must be delivered to the account owner; without SMTP, users should ask an administrator to reset the password.
- MFA uses TOTP apps. `cryptography` encrypts TOTP secrets at rest using `AUDIT_SECRET`; `qrcode` renders the setup QR. Keep the stable secret backed up. Recovery codes are single-use and shown once.
- Use the administrator **Users** workspace to add, invite, edit, activate, deactivate, reset MFA/password, change roles, and search accounts. Roles are Admin, Auditor, and User; the API enforces admin-only user management.
- Accounts see Security Settings for MFA, password, active sessions, session revocation, and security activity. Security events exclude passwords, raw tokens, and recovery codes.

If SMTP is not configured, self-registration and sign-in still work, but email password recovery and invitations are unavailable; an administrator can reset accounts in the Users workspace. MFA setup requires a stable `AUDIT_SECRET`. First-admin setup remains local.

For an always-on VPS deployment with a Caddy HTTPS reverse proxy, see [DEPLOYMENT.md](DEPLOYMENT.md). The backend and Android client share the HTTPS origin; the server uses a persistent `sentinel-data` volume. The service has `/healthz` and database-backed `/readyz` endpoints.

### Laptop and phone on the same LAN (Windows PowerShell)

The frontend and API run in one process and use the current page origin, so a phone and laptop connected to the same host see the same server-side SQLite data. In PowerShell, set a stable signing secret and bind the app only to the trusted LAN:

```powershell
$env:AUDIT_HOST = '0.0.0.0'
$env:AUDIT_PORT = '8080'
$env:AUDIT_SECRET = 'replace-with-a-unique-long-random-secret'
Set-Location -LiteralPath 'C:\path\to\sentinel-project'
.\run.bat
```

Replace and retain the secret across restarts. Keep Windows Firewall scoped to the Private profile/LAN; do not forward the port to the internet. Find the laptop IPv4 address with `ipconfig`, then open `http://<laptop-ip>:8080/` on a phone on the same trusted Wi-Fi. Laptop access remains `http://localhost:8080/`.

`AUDIT_API_URL` optionally sets an API origin when the UI is hosted separately. For that case set `AUDIT_CORS_ORIGIN` to the exact HTTPS UI origin; TLS is required for cross-origin cookie authentication. For LAN access, leave `AUDIT_API_URL` unset and use one same-origin server.

- Persistent server-side scan jobs keep real queued/running/completed/failed/cancelled state, status/progress, cancellation and retry. Refreshing/closing a browser does not terminate a job; interrupted jobs are marked failed at service restart.
- The Android client offers a separate, consent-based on-device audit for supported Android settings and launcher-visible app version inventory. It requires HTTPS and encrypts the app inventory at rest with `AUDIT_SECRET`; Android package visibility limits coverage, and app version observations alone are not presented as confirmed CVEs. See [android/README.md](android/README.md).
- Reset View clears temporary page/form/filter state and preserves saved records. A distinct admin-only Delete All Data action is destructive and requires typed confirmation.
## Included

- Password-hashed authentication, signed expiring sessions, role checks, CSRF protection, organization/project scoping, audit events, and input validation.
- Organization and project management, asset register, assessment templates, scan history, comparison, findings workflow, control register, compliance assessments, and risk scoring.
- Windows local assessment through read-only PowerShell/system inventory queries; Linux/macOS checks use read-only system APIs and standard tools.
- Authorized private IPv4 discovery up to /24 and public single globally routable IPv4 hosts (/32), each with explicit authorization. When Nmap is installed, single-host assessments perform full TCP discovery, light service/version detection, Nmap CPE collection and a conservative top-100 UDP scan; larger private ranges use bounded common-port checks.
- Evidence records identify collection source and verification state; inventory signatures are matched against a small, bundled CVE reference set. A match is a candidate requiring version confirmation, not proof of exploitability.
- Executive and technical report exports as JSON and PDF. The PDF renderer uses a minimal built-in implementation and needs no optional libraries.
- Searchable dashboard, findings filters, and REST API.

## Security assessment boundary

Network assessments require explicit authorization. A bare IPv4 address is assessed as that one host (/32); a CIDR must be a canonical network and is never widened silently. Private/loopback IPv4 ranges are capped at /24. Public targets must be literal, globally routable IPv4 addresses limited to one /32; public hostnames and wider CIDRs are rejected. With Nmap installed, single hosts receive full TCP discovery, light service/version detection, and bounded top-100 UDP checks. Network scopes use host discovery followed by detailed TCP and bounded UDP checks only for responsive hosts. Without Nmap, a bounded socket fallback first discovers responsive hosts and then checks a fixed common-port list. Set `AUDIT_NMAP_FULL_TCP=false` to use the top 1,000 TCP ports on a single host, or configure a bounded UDP list with `AUDIT_NMAP_UDP_PORTS` (up to 128 ports). The tool does not exploit services, authenticate, change configuration, or persist on targets. Reachability and CVE correlation do not prove vulnerability or exploitability. UDP open/filtered results remain candidates unless evidence confirms a response. Local assessment is read-only. Treat all results as point-in-time evidence and validate them before making production decisions.

The local assessment runs on the computer hosting Sentinel, including when started from the Android/WebView client. It requires explicit consent and records the authorization event. On Windows it queries update status, installed software, Defender, firewall profiles, BitLocker status (never recovery keys), Secure Boot, TPM, UAC, listening endpoints, and limited account posture. Unavailable or permission-limited checks are identified in the collected coverage metadata; lack of data is not reported as a secure result. The update query may contact the Windows Update or configured WSUS source. Per-app Windows permissions and Android phone internals are not assessed by this build.

To run a public assessment in the UI: choose **New network assessment**, enter the actual numeric public IPv4 address (optionally `/32`), check both authorization boxes, and queue it. The assessment originates from the Sentinel server. A laptop's internet-facing address often belongs to a router or carrier-grade NAT and does not identify a laptop reachable from outside; use **Assess server computer** for the computer running Sentinel. Do not scan a target unless you own it or have explicit authorization. Nmap is used when installed; otherwise the scanner falls back to the bounded common-port socket checks, which provide less coverage.

## Sentinel internal risk scoring

Each finding uses one deterministic business-risk calculation: **impact (0–10) × likelihood (1–5) ÷ 5 × asset criticality multiplier**, rounded to one decimal and capped at 10. Bands are critical (≥8), high (≥4.5), medium (≥2), low (≥0.1), and informational (0). The dashboard matrix counts active findings by likelihood and impact; its colors show the baseline formula using medium asset criticality. Individual finding scores use the actual linked asset criticality. **CVSS remains a separate technical score** and is never substituted for Sentinel's internal score. If an advisory match has not been explicitly verified, it is presented as a candidate even when collection evidence itself is verified.

## Configuration and operations

The SQLite schema uses `PRAGMA user_version` and applies migrations on startup. The database defaults to `./data/audit.db`. The application binds to loopback by default and refuses non-loopback binding unless `AUDIT_SECRET` is set. A production deployment should run behind TLS, restrict network access, set a unique signing secret, and use a dedicated OS account with least privilege. `python -m security_audit --check` verifies database initialization and core calculations. Run automated checks from the repository root with `$env:PYTHONPATH = "$PWD\security_audit"; python -m unittest discover -s tests -v`.

Optional NVD enrichment uses `NVD_API_KEY`, `NVD_TIMEOUT`, and `NVD_RESULTS_PER_PAGE` from the environment or `.env`; an NVD outage does not stop evidence collection. Nmap can be located through `NMAP_PATH`, `PATH`, or standard Windows install folders. `NMAP_TIMEOUT` remains the parent timeout setting; `NMAP_TCP_TIMEOUT`, `NMAP_UDP_TIMEOUT`, and `NMAP_DISCOVERY_TIMEOUT` set bounded per-phase timeouts. Set `AUDIT_NMAP_UDP_TOP` to change the conservative UDP top-port count. The bundled CVE reference set is intentionally small and offline. Extend it through `AUDIT_ADVISORY_FILE` with a JSON array of objects containing `cve`, `product`, `branch`, `affected_below`, `cvss`, `severity`, `source`, `url`, and `remediation`. Version candidates do not account for every vendor backport, distribution package epoch, or product rename; validate against the vendor advisory before treating one as confirmed.

## Extending

Assessment collectors, CVE references, and framework controls are isolated in `security_audit/assessments.py`, `security_audit/vulnerability.py`, and `security_audit/grc.py`. Add reference sources with provenance and licensing details; do not treat version-string candidates as confirmed vulnerabilities without validating vendor/product/version applicability.
