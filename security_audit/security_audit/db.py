"""SQLite storage and schema migrations."""
import os, sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS organizations(id INTEGER PRIMARY KEY, name TEXT NOT NULL, industry TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS memberships(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, role TEXT NOT NULL DEFAULT 'viewer', PRIMARY KEY(user_id,organization_id));
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), name TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', asset_type TEXT NOT NULL DEFAULT 'endpoint', criticality TEXT NOT NULL DEFAULT 'medium', owner TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(project_id,address));
CREATE TABLE IF NOT EXISTS assessments(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), asset_id INTEGER REFERENCES assets(id), kind TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'completed', started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, summary TEXT NOT NULL DEFAULT '{}', authorized_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), assessment_id INTEGER REFERENCES assessments(id), asset_id INTEGER REFERENCES assets(id), title TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'configuration', severity TEXT NOT NULL, likelihood INTEGER NOT NULL DEFAULT 3, impact INTEGER NOT NULL DEFAULT 5, risk_score REAL NOT NULL DEFAULT 3, description TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '{}', verified INTEGER NOT NULL DEFAULT 0, cve TEXT NOT NULL DEFAULT '', cvss REAL, control_ids TEXT NOT NULL DEFAULT '[]', remediation TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', assignee TEXT NOT NULL DEFAULT '', due_date TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS controls(id INTEGER PRIMARY KEY, framework TEXT NOT NULL, control_key TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', UNIQUE(framework,control_key));
CREATE TABLE IF NOT EXISTS control_results(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), control_id INTEGER NOT NULL REFERENCES controls(id), status TEXT NOT NULL DEFAULT 'not_assessed', evidence TEXT NOT NULL DEFAULT '', assessor TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(project_id,control_id));
CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', checks TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), project_id INTEGER REFERENCES projects(id), action TEXT NOT NULL, entity TEXT NOT NULL DEFAULT '', entity_id INTEGER, details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE, source TEXT NOT NULL, content TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id,status,severity);
CREATE INDEX IF NOT EXISTS idx_assessment_project ON assessments(project_id,completed_at);
"""
MIGRATION_2 = """
CREATE TABLE assets_new(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), name TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', asset_type TEXT NOT NULL DEFAULT 'endpoint', criticality TEXT NOT NULL DEFAULT 'medium', owner TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO assets_new SELECT id,project_id,name,hostname,address,asset_type,criticality,owner,notes,created_at FROM assets;
DROP TABLE assets;
ALTER TABLE assets_new RENAME TO assets;
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_project_address ON assets(project_id,address) WHERE address <> '';
"""
MIGRATION_3 = """
CREATE TABLE scan_jobs(id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), requested_by INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL CHECK(kind IN ('local','network')), target TEXT NOT NULL DEFAULT '', authorized INTEGER NOT NULL DEFAULT 0, public_authorized INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed','cancelled')), progress INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}', error TEXT NOT NULL DEFAULT '', cancel_requested INTEGER NOT NULL DEFAULT 0, retry_of TEXT REFERENCES scan_jobs(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX idx_scan_jobs_project ON scan_jobs(project_id,created_at);
"""
MIGRATION_4 = """
ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN is_email_verified INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN last_login_at TEXT;
ALTER TABLE users ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
UPDATE users SET updated_at=created_at WHERE updated_at='';
CREATE UNIQUE INDEX idx_users_username ON users(username COLLATE NOCASE) WHERE username<>'';
CREATE TABLE auth_tokens(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, used_at INTEGER, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX idx_auth_tokens_user_kind ON auth_tokens(user_id,kind,expires_at);
CREATE TABLE auth_sessions(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, session_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at INTEGER NOT NULL, revoked_at TEXT, ip_address TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id,expires_at,revoked_at);
CREATE TABLE mfa_recovery_codes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, code_hash TEXT NOT NULL UNIQUE, used_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE security_events(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, event TEXT NOT NULL, success INTEGER NOT NULL DEFAULT 1, ip_address TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX idx_security_events_user ON security_events(user_id,created_at);
CREATE TABLE auth_rate_limits(key_hash TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, window_started INTEGER NOT NULL, locked_until INTEGER NOT NULL DEFAULT 0);
"""
MIGRATION_5 = "ALTER TABLE users ADD COLUMN email_verification_skipped INTEGER NOT NULL DEFAULT 0;"
MIGRATION_6 = """
CREATE TABLE scan_jobs_new(id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), requested_by INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL CHECK(kind IN ('local','network','android_device')), target TEXT NOT NULL DEFAULT '', authorized INTEGER NOT NULL DEFAULT 0, public_authorized INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed','cancelled')), progress INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}', error TEXT NOT NULL DEFAULT '', cancel_requested INTEGER NOT NULL DEFAULT 0, retry_of TEXT REFERENCES scan_jobs_new(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO scan_jobs_new(id,project_id,requested_by,kind,target,authorized,public_authorized,status,progress,message,result,error,cancel_requested,retry_of,created_at,updated_at)
SELECT id,project_id,requested_by,kind,target,authorized,public_authorized,status,progress,message,result,error,cancel_requested,retry_of,created_at,updated_at FROM scan_jobs;
DROP TABLE scan_jobs;
ALTER TABLE scan_jobs_new RENAME TO scan_jobs;
CREATE INDEX idx_scan_jobs_project ON scan_jobs(project_id,created_at);
CREATE TABLE scan_job_inputs(job_id TEXT PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
"""
MIGRATION_7 = """
CREATE TABLE scan_jobs_new(id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), requested_by INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL CHECK(kind IN ('local','network','android_device','android_adb')), target TEXT NOT NULL DEFAULT '', authorized INTEGER NOT NULL DEFAULT 0, public_authorized INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed','cancelled')), progress INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}', error TEXT NOT NULL DEFAULT '', cancel_requested INTEGER NOT NULL DEFAULT 0, retry_of TEXT REFERENCES scan_jobs_new(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO scan_jobs_new(id,project_id,requested_by,kind,target,authorized,public_authorized,status,progress,message,result,error,cancel_requested,retry_of,created_at,updated_at)
SELECT id,project_id,requested_by,kind,target,authorized,public_authorized,status,progress,message,result,error,cancel_requested,retry_of,created_at,updated_at FROM scan_jobs;
DROP TABLE scan_jobs;
ALTER TABLE scan_jobs_new RENAME TO scan_jobs;
CREATE INDEX idx_scan_jobs_project ON scan_jobs(project_id,created_at);
"""
MIGRATION_8 = """
CREATE TABLE membership_requests(id INTEGER PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, email TEXT NOT NULL COLLATE NOCASE, full_name TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT, reviewed_by INTEGER REFERENCES users(id));
CREATE UNIQUE INDEX idx_membership_request_pending_email ON membership_requests(email COLLATE NOCASE) WHERE status='pending';
CREATE INDEX idx_membership_request_org ON membership_requests(organization_id,status,requested_at);
"""
MIGRATION_9 = """
CREATE TABLE scanner_agents(id TEXT PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at TEXT, revoked_at TEXT);
CREATE INDEX idx_scanner_agents_org ON scanner_agents(organization_id,revoked_at,last_seen_at);
ALTER TABLE scan_jobs ADD COLUMN scanner_agent_id TEXT REFERENCES scanner_agents(id);
"""
MIGRATIONS = ((1, SCHEMA),(2,MIGRATION_2),(3,MIGRATION_3),(4,MIGRATION_4),(5,MIGRATION_5),(6,MIGRATION_6),(7,MIGRATION_7),(8,MIGRATION_8),(9,MIGRATION_9))

def connect(path=None):
    location = path or os.environ.get("AUDIT_DB", "data/audit.db")
    if location != ":memory:": Path(location).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(location, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    version=db.execute("PRAGMA user_version").fetchone()[0]
    if version>len(MIGRATIONS): raise RuntimeError(f"Database schema version {version} is newer than this application")
    for number,script in MIGRATIONS:
        if version<number:
            if number in (2,6,7): db.execute("PRAGMA foreign_keys=OFF")
            try:
                db.executescript(f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version={number};\nCOMMIT;")
            except Exception:
                db.rollback()
                raise
            finally:
                if number in (2,6,7): db.execute("PRAGMA foreign_keys=ON")
            db.commit()
    return db

def rows(cursor): return [dict(r) for r in cursor.fetchall()]
