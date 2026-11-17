"""Authenticated REST API and static frontend server."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
import ssl
import re
import ipaddress
import sqlite3, datetime, logging
from pathlib import Path
import base64, hashlib, hmac, json, os, secrets, time, getpass, argparse, sys, threading, uuid
ROOT=Path(__file__).resolve().parents[2]
def load_environment_file():
    env_file=ROOT/".env"
    if not env_file.is_file(): return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line=line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        key,value=line.split("=",1); key=key.strip(); value=value.strip()
        if len(value)>=2 and value[0]==value[-1] and value[0] in ("'",'"'): value=value[1:-1]
        if re.fullmatch(r"[A-Z][A-Z0-9_]*",key): os.environ.setdefault(key,value)
load_environment_file()

from .db import connect, rows
from . import assessments, android_device, android_adb, risk, reports, grc, auth as authlib, correlation
LOG=logging.getLogger("sentinel.api")
def valid_signing_secret(value):
    candidate=(value or "").strip()
    return len(candidate)>=32 and not any(marker in candidate.lower() for marker in ("replace-with", "changeme", "change-me", "example-secret"))
configured_secret=os.environ.get("AUDIT_SECRET","").strip()
SECRET_CONFIGURED=valid_signing_secret(configured_secret)
SECRET=configured_secret if SECRET_CONFIGURED else secrets.token_urlsafe(48)
LOGIN_FAILURES={}
SCAN_EVENTS={}
SCAN_LOCK=threading.Lock()
def pw_hash(password,salt=None):
    if salt is not None:
        key=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
        return base64.b64encode(salt+key).decode()
    return authlib.password_hash(password)
def pw_verify(password,stored):
    return authlib.password_verify(password,stored)
def issue(user_id,session_id):
    payload=base64.urlsafe_b64encode(json.dumps({"uid":user_id,"sid":session_id,"exp":int(time.time())+28800},separators=(",",":")).encode()).decode().rstrip("=")
    sig=hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest(); return payload+"."+sig
def verify(token):
    try:
        body,sig=token.split("."); expected=hmac.new(SECRET.encode(),body.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected): return None
        data=json.loads(base64.urlsafe_b64decode(body+"="*(-len(body)%4)))
        return data if data["exp"]>time.time() else None
    except Exception: return None
class APIError(Exception):
    def __init__(self,status,message): self.status=status; self.message=message
class Handler(BaseHTTPRequestHandler):
    server_version="SentinelAudit/1.0"
    def log_message(self,format,*args):
        status=args[1] if len(args)>1 and str(args[1]).isdigit() else "-"
        LOG.info("client=%s method=%s path=%s status=%s",self.client_ip(),self.command,urlparse(self.path).path,status)
    def client_ip(self):
        peer=str(self.client_address[0])
        if os.environ.get("TRUST_PROXY_HEADERS","").lower() in ("1","true","yes"):
            forwarded=self.headers.get("X-Real-IP","").strip()
            try: return str(ipaddress.ip_address(forwarded))
            except ValueError: pass
        return peer
    def secure_transport(self):
        if isinstance(self.connection, ssl.SSLSocket): return True
        return os.environ.get("TRUST_PROXY_HEADERS","").lower() in ("1","true","yes") and self.headers.get("X-Forwarded-Proto","").lower()=="https"
    def send_json(self,obj,status=200,extra_headers=()):
        body=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Content-Security-Policy",self.csp());
        self.cors_headers()
        for name,value in extra_headers:self.send_header(name,value)
        self.end_headers(); self.wfile.write(body)
    def cors_headers(self):
        allowed=os.environ.get("AUDIT_CORS_ORIGIN","").rstrip("/"); origin=self.headers.get("Origin","").rstrip("/")
        if allowed and origin==allowed:
            self.send_header("Access-Control-Allow-Origin",allowed); self.send_header("Access-Control-Allow-Credentials","true"); self.send_header("Access-Control-Allow-Headers","Content-Type, X-CSRF-Token"); self.send_header("Access-Control-Allow-Methods","GET, POST, PATCH, DELETE, OPTIONS"); self.send_header("Vary","Origin")
    def csp(self):
        api_url=os.environ.get("AUDIT_API_URL",""); api_origin=""
        if api_url:
            parsed=urlparse(api_url); api_origin=f"{parsed.scheme}://{parsed.netloc}"
        return "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com "+api_origin+"; frame-ancestors 'none'"
    def send_file(self,path,kind):
        body=path.read_bytes(); self.send_response(200); self.send_header("Content-Type",kind); self.send_header("Content-Length",str(len(body))); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","same-origin"); self.send_header("Content-Security-Policy",self.csp()); self.cors_headers(); self.end_headers(); self.wfile.write(body)
    def body(self):
        try: n=int(self.headers.get("Content-Length","0"))
        except ValueError: raise APIError(400,"Invalid content length")
        if n>1048576: raise APIError(413,"Request too large")
        if not n:return {}
        try: x=json.loads(self.rfile.read(n)); return x if isinstance(x,dict) else (_ for _ in ()).throw(ValueError())
        except Exception: raise APIError(400,"Expected a JSON object")
    def cookies(self):
        return dict(part.strip().split("=",1) for part in self.headers.get("Cookie","").split(";") if "=" in part)
    def auth(self,db,write=False):
        cookie=self.cookies().get("audit_session",""); claims=verify(cookie); uid=claims.get("uid") if claims else None
        user=db.execute("SELECT id,email,role,is_active,is_email_verified,email_verification_skipped,require_mfa,mfa_enabled FROM users WHERE id=?",(uid,)).fetchone() if uid else None
        if not user or not user["is_active"]: raise APIError(401,"Sign in required")
        if not user["is_email_verified"] and not user["email_verification_skipped"]: raise APIError(403,"Verify your email before signing in")
        sid=claims.get("sid") if claims else None; session_hash=hashlib.sha256((sid or cookie).encode()).hexdigest()
        session=db.execute("SELECT id,expires_at,revoked_at FROM auth_sessions WHERE session_hash=? AND user_id=?",(session_hash,user["id"])).fetchone()
        if session and (session["revoked_at"] or session["expires_at"]<int(time.time())): raise APIError(401,"Session expired; sign in again")
        if not session and sid:
            raise APIError(401,"Session expired; sign in again")
        if not session: # Adopt a valid session cookie issued before session tracking was introduced.
            db.execute("INSERT INTO auth_sessions(user_id,session_hash,expires_at,ip_address,user_agent) VALUES(?,?,?,?,?)",(user["id"],session_hash,claims["exp"],self.client_ip(),self.headers.get("User-Agent","")[:400]))
            session=db.execute("SELECT id,expires_at,revoked_at FROM auth_sessions WHERE session_hash=?",(session_hash,)).fetchone()
        db.execute("UPDATE auth_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?",(session["id"],))
        db.commit()
        if user["require_mfa"] and not user["mfa_enabled"] and urlparse(self.path).path not in ("/api/auth/me","/api/auth/logout","/api/auth/mfa/setup","/api/auth/mfa/enable","/api/auth/sessions","/api/auth/security-events"):
            raise APIError(403,"Set up multi-factor authentication before using this account")
        if write and (not self.cookies().get("audit_csrf") or not hmac.compare_digest(self.cookies().get("audit_csrf",""),self.headers.get("X-CSRF-Token",""))): raise APIError(403,"CSRF validation failed")
        result={"id":user["id"],"email":user["email"],"role":user["role"],"_session_id":session["id"]}
        profile=db.execute("SELECT full_name,username,is_email_verified,email_verification_skipped,mfa_enabled,require_mfa,last_login_at FROM users WHERE id=?",(user["id"],)).fetchone()
        result.update(dict(profile))
        return result
    def audit(self,db,user,action,entity="",entity_id=None,details=None,project_id=None):
        db.execute("INSERT INTO audit_log(user_id,project_id,action,entity,entity_id,details) VALUES(?,?,?,?,?,?)",(user["id"],project_id,action,entity,entity_id,json.dumps(details or {})))
    def security_event(self,db,event,user_id=None,success=True,details=None):
        db.execute("INSERT INTO security_events(user_id,event,success,ip_address,user_agent,details) VALUES(?,?,?,?,?,?)",(user_id,event,int(success),self.client_ip(),self.headers.get("User-Agent","")[:400],json.dumps(details or {})))
    def throttle(self,db,key,maximum=5,window=900):
        now=int(time.time()); digest=hashlib.sha256((self.client_ip()+"|"+key).encode()).hexdigest(); row=db.execute("SELECT failures,window_started,locked_until FROM auth_rate_limits WHERE key_hash=?",(digest,)).fetchone()
        if row and (row["locked_until"]>now or (now-row["window_started"]<window and row["failures"]>=maximum)):
            raise APIError(429,"Too many requests. Wait and try again.")
        failures=(row["failures"]+1 if row and now-row["window_started"]<window else 1); start=row["window_started"] if row and now-row["window_started"]<window else now
        locked=now+window if failures>=maximum else 0
        db.execute("INSERT INTO auth_rate_limits(key_hash,failures,window_started,locked_until) VALUES(?,?,?,?) ON CONFLICT(key_hash) DO UPDATE SET failures=excluded.failures,window_started=excluded.window_started,locked_until=excluded.locked_until",(digest,failures,start,locked))
        db.commit()
    def clear_throttle(self,db,key):
        digest=hashlib.sha256((self.client_ip()+"|"+key).encode()).hexdigest()
        db.execute("DELETE FROM auth_rate_limits WHERE key_hash=?",(digest,))
    def require_unlocked(self,db,key,message="Too many attempts. Wait and try again."):
        digest=hashlib.sha256((self.client_ip()+"|"+key).encode()).hexdigest(); row=db.execute("SELECT failures,window_started,locked_until FROM auth_rate_limits WHERE key_hash=?",(digest,)).fetchone(); now=int(time.time())
        if row and (row["locked_until"]>now or (now-row["window_started"]<900 and row["failures"]>=5)): raise APIError(429,message)
    def session_cookie_headers(self,token,csrf,max_age=28800):
        cross_origin=bool(os.environ.get("AUDIT_CORS_ORIGIN")); secure="; Secure" if cross_origin or os.environ.get("AUDIT_COOKIE_SECURE","").lower() in ("1","true","yes") else ""; same_site="None" if cross_origin else "Strict"
        return [("Set-Cookie",f"audit_session={token}; HttpOnly; SameSite={same_site}; Path=/; Max-Age={max_age}{secure}"),("Set-Cookie",f"audit_csrf={csrf}; SameSite={same_site}; Path=/; Max-Age={max_age}{secure}")]
    def issue_session(self,db,user_id):
        sid=authlib.token(); csrf=secrets.token_urlsafe(24); expiry=int(time.time())+28800
        db.execute("INSERT INTO auth_sessions(user_id,session_hash,expires_at,ip_address,user_agent) VALUES(?,?,?,?,?)",(user_id,hashlib.sha256(sid.encode()).hexdigest(),expiry,self.client_ip(),self.headers.get("User-Agent","")[:400]))
        return issue(user_id,sid),csrf
    def project(self,db,user,pid,write=False):
        if user.get("role")=="admin":
            p=db.execute("SELECT p.*, 'admin' organization_role FROM projects p WHERE p.id=?",(pid,)).fetchone()
        else:
            p=db.execute("SELECT p.*,m.role organization_role FROM projects p JOIN memberships m ON m.organization_id=p.organization_id WHERE p.id=? AND m.user_id=?",(pid,user["id"])).fetchone()
        if not p: raise APIError(404,"Project not found")
        if write and p["organization_role"] not in ("admin","analyst") and user["role"]!="admin": raise APIError(403,"Project write access required")
        return dict(p)
    def org(self,db,user,oid):
        if user.get("role")=="admin": o=db.execute("SELECT o.* FROM organizations o WHERE o.id=?",(oid,)).fetchone()
        else: o=db.execute("SELECT o.* FROM organizations o JOIN memberships m ON m.organization_id=o.id WHERE o.id=? AND m.user_id=?",(oid,user["id"])).fetchone()
        if not o: raise APIError(404,"Organization not found")
        return dict(o)
    def org_admin(self,db,user,oid):
        if user.get("role")=="admin":
            self.org(db,user,oid); return
        self.org(db,user,oid)
        role=db.execute("SELECT role FROM memberships WHERE user_id=? AND organization_id=?",(user["id"],oid)).fetchone()[0]
        if role!="admin": raise APIError(403,"Organization administrator access required")
    def assessment_access(self,db,user,pid,assessment_id):
        project=self.project(db,user,pid)
        assessment=db.execute("SELECT authorized_by FROM assessments WHERE id=? AND project_id=?",(assessment_id,pid)).fetchone()
        if not assessment or (project["organization_role"]!="admin" and user.get("role")!="admin" and assessment["authorized_by"]!=user["id"]): raise APIError(404,"Assessment not found in this project")
        return assessment
    def route_agent(self,db,path,method,data):
        if not self.secure_transport() and self.client_ip() not in ("127.0.0.1","::1"):
            raise APIError(400,"Scanner agents must connect over HTTPS")
        raw=self.headers.get("Authorization","")
        token=raw[7:].strip() if raw.lower().startswith("bearer ") else ""
        if not token or len(token)>256: raise APIError(401,"Valid scanner agent token required")
        agent=db.execute("SELECT * FROM scanner_agents WHERE token_hash=? AND revoked_at IS NULL",(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not agent: raise APIError(401,"Scanner agent token is invalid or revoked")
        now=datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.execute("UPDATE scanner_agents SET last_seen_at=? WHERE id=?",(now,agent["id"]))
        db.commit()
        if path=="/api/agent/next" and method=="GET":
            db.execute("BEGIN IMMEDIATE")
            job=db.execute("SELECT id,target,authorized,public_authorized FROM scan_jobs WHERE scanner_agent_id=? AND kind='network' AND status='queued' ORDER BY created_at LIMIT 1",(agent["id"],)).fetchone()
            if job:
                claimed=db.execute("UPDATE scan_jobs SET status='running',progress=1,message='Private network scan claimed by organization agent',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='queued'",(job["id"],)).rowcount
                if not claimed: job=None
            db.commit()
            self.send_json({"job":({"id":job["id"],"target":job["target"],"authorized":bool(job["authorized"]),"public_authorized":bool(job["public_authorized"])} if job else None)}); return
        match_result=re.fullmatch(r"/api/agent/jobs/([a-f0-9]{32})/result",path)
        match_progress=re.fullmatch(r"/api/agent/jobs/([a-f0-9]{32})/progress",path)
        if match_progress and method=="POST":
            job=db.execute("SELECT id,cancel_requested FROM scan_jobs WHERE id=? AND scanner_agent_id=? AND status='running'",(match_progress.group(1),agent["id"])).fetchone()
            if not job: raise APIError(404,"Assigned running scan job not found")
            if job["cancel_requested"]:
                self.send_json({"cancelled":True}); return
            try: value=int(data.get("progress",0))
            except (TypeError,ValueError): raise APIError(400,"Progress must be an integer from 0 to 99")
            if value<0 or value>99: raise APIError(400,"Progress must be an integer from 0 to 99")
            message=str(data.get("message","Private network checks running"))[:240]
            db.execute("UPDATE scan_jobs SET progress=?,message=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'",(value,message,job["id"])); db.commit(); self.send_json({"cancelled":False}); return
        if match_result and method=="POST":
            job_id=match_result.group(1)
            job=db.execute("SELECT * FROM scan_jobs WHERE id=? AND scanner_agent_id=? AND kind='network' AND status='running'",(job_id,agent["id"])).fetchone()
            if not job: raise APIError(404,"Assigned running scan job not found")
            if job["cancel_requested"]:
                db.execute("UPDATE scan_jobs SET status='cancelled',message='Assessment cancelled',error='',updated_at=CURRENT_TIMESTAMP WHERE id=?",(job_id,)); db.commit(); self.send_json({"ok":True,"status":"cancelled"}); return
            if data.get("error"):
                error=str(data["error"])[:500]
                db.execute("UPDATE scan_jobs SET status='failed',message='Private network agent scan failed',error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(error,job_id))
                db.execute("INSERT INTO audit_log(user_id,project_id,action,entity,entity_id,details) VALUES(?,?, 'scan.failed','scan_job',?,?)",(job["requested_by"],job["project_id"],None,json.dumps({"job_id":job_id,"scanner_agent_id":agent["id"],"error":error}))); db.commit(); self.send_json({"ok":True,"status":"failed"}); return
            result=data.get("result")
            if not isinstance(result,dict) or not isinstance(result.get("findings",[]),list) or not isinstance(result.get("hosts",[]),list): raise APIError(400,"Scanner result format is invalid")
            if len(result.get("findings",[]))>300 or len(result.get("hosts",[]))>256: raise APIError(413,"Scanner result exceeds the accepted scope limits")
            scope=assessments.validate_scope(job["target"],bool(job["authorized"]),bool(job["public_authorized"]))
            if str(result.get("scope",""))!=str(scope): raise APIError(400,"Scanner result scope does not match the authorized job scope")
            for host in result["hosts"]:
                try: address=ipaddress.ip_address(host["address"])
                except (KeyError,ValueError,TypeError): raise APIError(400,"Scanner result contains an invalid host address")
                if address not in scope: raise APIError(400,"Scanner result contains a host outside the authorized scope")
            result["source"]="organization scanner agent"
            userrow=db.execute("SELECT id,email,role FROM users WHERE id=?",(job["requested_by"],)).fetchone()
            assessment_id=persist_assessment(db,dict(userrow),job["project_id"],None,"network",result)
            for host in result["hosts"]:
                addr=host["address"]; name=str(host.get("hostname",addr))[:253]
                row=db.execute("SELECT id FROM assets WHERE project_id=? AND address=? ORDER BY id LIMIT 1",(job["project_id"],addr)).fetchone()
                if row: db.execute("UPDATE assets SET hostname=? WHERE id=?",(name,row["id"]))
                else: db.execute("INSERT INTO assets(project_id,name,hostname,address,asset_type) VALUES(?,?,?,?, 'network')",(job["project_id"],name,name,addr))
            job_result={"assessment_id":assessment_id,"summary":result.get("summary",{}),"scope":result.get("scope"),"scope_details":result.get("scope_details",{}),"network_summary":result.get("network_summary",{}),"severity_counts":result.get("severity_counts",{}),"hosts":result.get("hosts",[]),"services":result.get("services",[]),"findings":len(result.get("findings",[])),"warnings":result.get("warnings",result.get("scope_details",{}).get("warnings",[])),"source":"organization scanner agent"}
            db.execute("UPDATE scan_jobs SET status='completed',progress=100,message='Private network assessment completed by organization agent',result=?,error='',updated_at=CURRENT_TIMESTAMP WHERE id=?",(json.dumps(job_result),job_id)); db.execute("INSERT INTO audit_log(user_id,project_id,action,entity,entity_id,details) VALUES(?,?, 'scan.agent_completed','assessment',?,?)",(job["requested_by"],job["project_id"],assessment_id,json.dumps({"job_id":job_id,"scanner_agent_id":agent["id"],"scope":job["target"]}))); db.commit(); self.send_json({"ok":True,"status":"completed","assessment_id":assessment_id}); return
        raise APIError(404,"Scanner agent endpoint not found")
    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_PATCH(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def do_OPTIONS(self): self.handle_request()
    def handle_request(self):
        db=connect()
        try:
            path=urlparse(self.path).path; q=parse_qs(urlparse(self.path).query); method=self.command
            if path=="/healthz" and method=="GET": self.send_json({"status":"ok"}); return
            if path=="/readyz" and method=="GET":
                db.execute("SELECT 1").fetchone()
                self.send_json({"status":"ready","database":"ok"}); return
            if path.startswith("/api/") and method=="OPTIONS": self.send_response(204); self.cors_headers(); self.send_header("Content-Length","0"); self.end_headers(); return
            if path=="/config.js" and method=="GET":
                value=json.dumps(os.environ.get("AUDIT_API_URL","").rstrip("/")); captcha=json.dumps(os.environ.get("CAPTCHA_SITE_KEY","")); captcha_ready=json.dumps(authlib.captcha_configured()); email_ready=json.dumps(authlib.smtp_configured()); body=f"window.AUDIT_API_URL={value};window.AUDIT_CAPTCHA_SITE_KEY={captcha};window.AUDIT_ACCOUNT_CAPTCHA_READY={captcha_ready};window.AUDIT_ACCOUNT_EMAIL_READY={email_ready};".encode(); self.send_response(200); self.send_header("Content-Type","text/javascript; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(body); return
            if path.startswith("/api/"): self.route(db,path,q); return
            if method!="GET": raise APIError(405,"Method not allowed")
            file={"/":"index.html","/app.js":"app.js","/auth-enhancements.js":"auth-enhancements.js","/style.css":"style.css","/refresh-button.js":"refresh-button.js","/manifest.webmanifest":"manifest.webmanifest","/icon.svg":"icon.svg"}.get(path)
            if file:
                kind={"/":"text/html; charset=utf-8","/manifest.webmanifest":"application/manifest+json; charset=utf-8","/icon.svg":"image/svg+xml"}.get(path,"text/javascript; charset=utf-8" if file.endswith("js") else "text/css; charset=utf-8")
                self.send_file(ROOT/"web"/file,kind); return
            raise APIError(404,"Not found")
        except APIError as e: self.send_json({"error":e.message},e.status)
        except ValueError as e: self.send_json({"error":str(e)},400)
        except sqlite3.IntegrityError: self.send_json({"error":"The change conflicts with existing data or a referenced record"},409)
        except Exception as e:
            LOG.exception("Unhandled request error method=%s path=%s",self.command,urlparse(self.path).path)
            self.send_json({"error":"Internal server error"},500)
        finally: db.close()
    def route(self,db,path,q):
        method=self.command; data=self.body() if method in ("POST","PATCH","DELETE") else {}
        # Scanner agents authenticate with a per-agent bearer token, never a
        # browser cookie. Their token is organization-bound and revocable.
        if path.startswith("/api/agent/"):
            self.route_agent(db,path,method,data)
            return
        if path=="/api/auth/registration-organizations" and method=="GET":
            self.send_json({"organizations":rows(db.execute("SELECT id,name FROM organizations ORDER BY name LIMIT 500"))}); return
        if path=="/api/auth/register" and method=="POST":
            self.throttle(db,"register",8,3600)
            email=required(data,"email",254).lower(); password=data.get("password","")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,63}",email): raise ValueError("Enter a valid email address")
            if not authlib.valid_password(password): raise ValueError("Password must be 6–256 characters")
            if password!=data.get("confirm_password"): raise ValueError("Passwords do not match")
            try: organization_id=int(data.get("organization_id",0))
            except (TypeError,ValueError): raise ValueError("Choose an organization")
            org=db.execute("SELECT id FROM organizations WHERE id=?",(organization_id,)).fetchone()
            if not org: raise ValueError("Choose an existing organization")
            if db.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE",(email,)).fetchone(): raise APIError(409,"An account already exists for this email")
            if db.execute("SELECT 1 FROM membership_requests WHERE email=? COLLATE NOCASE AND status='pending'",(email,)).fetchone(): raise APIError(409,"An account request for this email is already waiting for approval")
            full_name=required(data,"full_name",120) if data.get("full_name") else email.split("@",1)[0][:120]
            db.execute("INSERT INTO membership_requests(organization_id,email,full_name,password_hash) VALUES(?,?,?,?)",(organization_id,email,full_name,pw_hash(password)))
            self.security_event(db,"membership_request_submitted",None,True,{"organization_id":organization_id,"email":email}); db.commit(); self.send_json({"ok":True,"message":"Account request submitted. An organization administrator must approve it before you can sign in."},201); return
        if path=="/api/auth/verify-email" and method=="POST":
            raw=required(data,"token",256); row=db.execute("SELECT id,user_id FROM auth_tokens WHERE kind='email_verify' AND token_hash=? AND used_at IS NULL AND expires_at>=?",(authlib.token_hash(raw),int(time.time()))).fetchone()
            if not row: raise APIError(400,"Verification code is invalid or expired")
            claimed=db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL AND expires_at>=?",(row["id"],int(time.time()))).rowcount
            if not claimed: raise APIError(400,"Verification code is invalid or expired")
            db.execute("UPDATE users SET is_email_verified=1,updated_at=CURRENT_TIMESTAMP WHERE id=?",(row["user_id"],)); self.security_event(db,"email_verified",row["user_id"]); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/auth/accept-invite" and method=="POST":
            raw=required(data,"token",256); password=data.get("password","")
            if not authlib.valid_password(password) or password!=data.get("confirm_password"): raise ValueError("Choose a matching password with at least 6 characters")
            invite=db.execute("SELECT id,user_id FROM auth_tokens WHERE kind='invitation' AND token_hash=? AND used_at IS NULL AND expires_at>=?",(authlib.token_hash(raw),int(time.time()))).fetchone()
            if not invite: raise APIError(400,"Invitation is invalid or expired")
            claimed=db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL AND expires_at>=?",(invite["id"],int(time.time()))).rowcount
            if not claimed: raise APIError(400,"Invitation is invalid or expired")
            db.execute("UPDATE users SET password_hash=?,is_email_verified=1,updated_at=CURRENT_TIMESTAMP WHERE id=?",(pw_hash(password),invite["user_id"])); self.security_event(db,"invitation_accepted",invite["user_id"]); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/auth/resend-verification" and method=="POST":
            self.throttle(db,"resend-verification",3,3600)
            if not authlib.captcha_configured(): raise APIError(503,"Email verification is unavailable: configure CAPTCHA_SITE_KEY and CAPTCHA_SECRET_KEY in .env, then restart Sentinel Audit.")
            if not authlib.smtp_configured(): raise APIError(503,"Email verification is unavailable: configure SMTP_HOST and SMTP_FROM in .env, then restart Sentinel Audit.")
            if not authlib.verify_captcha(data.get("captcha_token"),self.client_ip()): raise APIError(400,"Complete the security check and try again")
            email=str(data.get("email","")).strip().lower(); row=db.execute("SELECT id,is_email_verified FROM users WHERE email=?",(email,)).fetchone()
            if row and not row["is_email_verified"] and authlib.smtp_configured():
                raw=authlib.token(); db.execute("INSERT INTO auth_tokens(user_id,kind,token_hash,expires_at) VALUES(?,?,?,?)",(row["id"],"email_verify",authlib.token_hash(raw),int(time.time())+86400))
                try: authlib.send_email(email,"Verify your Sentinel Audit account","Your one-time verification code is: "+raw)
                except Exception: db.rollback(); self.send_json({"ok":True,"message":"If the address needs verification, a message will be sent."}); return
            db.commit(); self.send_json({"ok":True,"message":"If the address needs verification, a message will be sent."}); return
        if path=="/api/auth/forgot-password" and method=="POST":
            self.throttle(db,"forgot-password:"+str(data.get("email",""))[:254].lower(),5,3600)
            if not authlib.smtp_configured(): raise APIError(503,"Password recovery is unavailable: configure SMTP_HOST and SMTP_FROM in .env, then restart Sentinel Audit.")
            email=str(data.get("email","")).strip().lower(); row=db.execute("SELECT id,is_active FROM users WHERE email=?",(email,)).fetchone()
            if row and row["is_active"] and authlib.smtp_configured():
                raw=authlib.token(); db.execute("INSERT INTO auth_tokens(user_id,kind,token_hash,expires_at) VALUES(?,?,?,?)",(row["id"],"password_reset",authlib.token_hash(raw),int(time.time())+1800)); url=os.environ.get("AUDIT_PUBLIC_URL","").rstrip("/")
                text="Your Sentinel Audit password reset code is: "+raw+"\nIt expires in 30 minutes."
                if url: text+="\n\nOpen: "+url+"/?reset_password="+quote(raw)
                try: authlib.send_email(email,"Reset your Sentinel Audit password",text)
                except Exception: pass
            db.commit(); self.send_json({"ok":True,"message":"If an eligible account exists, a password reset message will be sent."}); return
        if path=="/api/auth/reset-password" and method=="POST":
            raw=required(data,"token",256); password=data.get("password","")
            if not authlib.valid_password(password) or password!=data.get("confirm_password"): raise ValueError("Choose a matching password with at least 6 characters")
            row=db.execute("SELECT id,user_id FROM auth_tokens WHERE kind='password_reset' AND token_hash=? AND used_at IS NULL AND expires_at>=?",(authlib.token_hash(raw),int(time.time()))).fetchone()
            if not row: raise APIError(400,"Reset code is invalid or expired")
            claimed=db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL AND expires_at>=?",(row["id"],int(time.time()))).rowcount
            if not claimed: raise APIError(400,"Reset code is invalid or expired")
            db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND kind='password_reset' AND used_at IS NULL",(row["user_id"],)); db.execute("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(pw_hash(password),row["user_id"])); db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL",(row["user_id"],)); self.security_event(db,"password_reset",row["user_id"]); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/auth/login" and method=="POST":
            email=str(data.get("email","" )).strip().lower(); user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); now=int(time.time()); client=self.client_ip()
            key=hashlib.sha256((client+"|"+email).encode()).hexdigest(); limit=db.execute("SELECT * FROM auth_rate_limits WHERE key_hash=?",(key,)).fetchone()
            if limit and limit["locked_until"]>now: raise APIError(429,"Too many sign-in attempts. Wait and try again.")
            failures=limit["failures"] if limit and now-limit["window_started"]<900 else 0
            if failures>=3 and authlib.captcha_configured() and not authlib.verify_captcha(data.get("captcha_token"),client): raise APIError(400,"Complete the security check and try again")
            password=str(data.get("password","")); valid=pw_verify(password,user["password_hash"]) if user else (authlib.dummy_password_check(password) or False)
            if not user or not valid or not user["is_active"] or (not user["is_email_verified"] and not user["email_verification_skipped"]):
                failures=failures+1 if limit and now-limit["window_started"]<900 else 1; locked=now+(min(900,30*(2**max(0,failures-5))) if failures>=5 else 0)
                db.execute("INSERT INTO auth_rate_limits(key_hash,failures,window_started,locked_until) VALUES(?,?,?,?) ON CONFLICT(key_hash) DO UPDATE SET failures=excluded.failures,window_started=excluded.window_started,locked_until=excluded.locked_until",(key,failures,now,locked)); self.security_event(db,"login",user["id"] if user else None,False); db.commit(); raise APIError(401,"Email or password is incorrect")
            db.execute("DELETE FROM auth_rate_limits WHERE key_hash=?",(key,))
            if authlib.password_needs_upgrade(user["password_hash"]): db.execute("UPDATE users SET password_hash=? WHERE id=?",(pw_hash(password),user["id"]))
            if user["mfa_enabled"]:
                challenge=authlib.token(); db.execute("INSERT INTO auth_tokens(user_id,kind,token_hash,expires_at) VALUES(?,?,?,?)",(user["id"],"mfa_challenge",authlib.token_hash(challenge),now+300)); db.commit(); self.send_json({"mfa_required":True,"challenge":challenge}); return
            cookie,csrf=self.issue_session(db,user["id"])
            if user["require_mfa"]:
                db.commit(); self.send_json({"mfa_setup_required":True,"csrf_token":csrf},extra_headers=self.session_cookie_headers(cookie,csrf)); return
            db.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?",(user["id"],)); self.security_event(db,"login",user["id"]); db.commit(); self.send_json({"user":{"id":user["id"],"email":email,"role":user["role"]},"csrf_token":csrf},extra_headers=self.session_cookie_headers(cookie,csrf)); return
        if path=="/api/auth/mfa/verify" and method=="POST":
            raw=required(data,"challenge",256); self.throttle(db,"mfa-verify:"+authlib.token_hash(raw),5,900); db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT t.id,t.user_id,u.mfa_secret FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.kind='mfa_challenge' AND t.token_hash=? AND t.used_at IS NULL AND t.expires_at>=? AND u.mfa_enabled=1 AND u.is_active=1 AND (u.is_email_verified=1 OR u.email_verification_skipped=1)",(authlib.token_hash(raw),int(time.time()))).fetchone()
            if row: self.require_unlocked(db,"mfa-account:"+str(row["user_id"]),"Too many authenticator failures. Sign in again later.")
            ok=False
            if row:
                secret=authlib.decrypt_secret(row["mfa_secret"],SECRET); code=str(data.get("code","")); ok=authlib.verify_totp(secret,code)
                if not ok:
                    code_hash=authlib.token_hash(code.upper()); recovery=db.execute("SELECT id FROM mfa_recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL",(row["user_id"],code_hash)).fetchone()
                    if recovery: ok=db.execute("UPDATE mfa_recovery_codes SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL",(recovery["id"],)).rowcount==1
            if not ok:
                if row: self.throttle(db,"mfa-account:"+str(row["user_id"]),5,900)
                self.security_event(db,"mfa_login",row["user_id"] if row else None,False); db.commit(); raise APIError(401,"Verification failed. Sign in again and retry.")
            self.clear_throttle(db,"mfa-verify:"+authlib.token_hash(raw))
            self.clear_throttle(db,"mfa-account:"+str(row["user_id"]))
            claimed=db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL AND expires_at>=?",(row["id"],int(time.time()))).rowcount
            if not claimed: db.rollback(); raise APIError(401,"Verification failed. Sign in again and retry.")
            cookie,csrf=self.issue_session(db,row["user_id"]); db.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?",(row["user_id"],)); self.security_event(db,"mfa_login",row["user_id"]); db.commit(); self.send_json({"ok":True,"csrf_token":csrf},extra_headers=self.session_cookie_headers(cookie,csrf)); return
        if path=="/api/auth/me" and method=="GET":
            user=self.auth(db); user.pop("_session_id",None); csrf=secrets.token_urlsafe(24); db.commit(); self.send_json({"user":user,"csrf_token":csrf},extra_headers=self.session_cookie_headers(self.cookies().get("audit_session",""),csrf)); return
        if path=="/api/auth/logout" and method=="POST":
            user=self.auth(db,True); db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=?",(user["_session_id"],)); self.security_event(db,"logout",user["id"]); db.commit(); headers=self.session_cookie_headers("", "", 0); self.send_json({"ok":True},extra_headers=headers); return
        user=self.auth(db,method in ("POST","PATCH","DELETE")); segments=path.strip("/").split("/")
        if path=="/api/auth/mfa/setup" and method=="POST":
            if not SECRET_CONFIGURED: raise APIError(503,"Set a stable AUDIT_SECRET before configuring multi-factor authentication")
            row=db.execute("SELECT mfa_enabled FROM users WHERE id=?",(user["id"],)).fetchone()
            if row["mfa_enabled"]: raise APIError(409,"MFA is already enabled")
            secret=authlib.new_totp_secret()
            try: encrypted_secret=authlib.encrypt_secret(secret,SECRET)
            except ImportError: raise APIError(503,"Install the required MFA dependencies with: python -m pip install -r requirements.txt")
            db.execute("UPDATE users SET mfa_secret=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(encrypted_secret,user["id"])); db.commit()
            label=quote(user["email"]); issuer=quote("Sentinel Audit"); uri=f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
            try: qr=authlib.qr_data_uri(uri)
            except ImportError: qr=""
            self.send_json({"secret":secret,"otpauth_uri":uri,"qr_data_uri":qr}); return
        if path=="/api/auth/mfa/enable" and method=="POST":
            row=db.execute("SELECT mfa_secret,mfa_enabled FROM users WHERE id=?",(user["id"],)).fetchone()
            if row["mfa_enabled"] or not row["mfa_secret"]: raise APIError(409,"Start MFA setup first")
            secret=authlib.decrypt_secret(row["mfa_secret"],SECRET)
            if not authlib.verify_totp(secret,str(data.get("code",""))): self.throttle(db,"mfa-enable:"+str(user["id"]),5,900); self.security_event(db,"mfa_enabled",user["id"],False); db.commit(); raise APIError(400,"Authenticator code is invalid")
            self.clear_throttle(db,"mfa-enable:"+str(user["id"]))
            codes=authlib.recovery_codes(); db.execute("UPDATE users SET mfa_enabled=1,updated_at=CURRENT_TIMESTAMP WHERE id=?",(user["id"],)); db.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(user["id"],)); db.executemany("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)",[(user["id"],authlib.token_hash(c)) for c in codes]); db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND id<>? AND revoked_at IS NULL",(user["id"],user["_session_id"])); self.security_event(db,"mfa_enabled",user["id"]); db.commit(); self.send_json({"ok":True,"recovery_codes":codes}); return
        if path=="/api/auth/mfa/disable" and method=="POST":
            row=db.execute("SELECT password_hash,mfa_enabled,mfa_secret FROM users WHERE id=?",(user["id"],)).fetchone()
            if not row["mfa_enabled"]: raise APIError(409,"MFA is not enabled")
            valid=pw_verify(str(data.get("password","")),row["password_hash"])
            if valid:
                secret=authlib.decrypt_secret(row["mfa_secret"],SECRET); valid=authlib.verify_totp(secret,str(data.get("code","")))
            if not valid: self.throttle(db,"mfa-disable:"+str(user["id"]),5,900); self.security_event(db,"mfa_disabled",user["id"],False); db.commit(); raise APIError(401,"Re-authentication failed")
            self.clear_throttle(db,"mfa-disable:"+str(user["id"]))
            db.execute("UPDATE users SET mfa_enabled=0,mfa_secret='',updated_at=CURRENT_TIMESTAMP WHERE id=?",(user["id"],)); db.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(user["id"],)); self.security_event(db,"mfa_disabled",user["id"]); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/auth/mfa/recovery-codes" and method=="POST":
            row=db.execute("SELECT mfa_enabled,mfa_secret FROM users WHERE id=?",(user["id"],)).fetchone()
            if not row["mfa_enabled"] or not authlib.verify_totp(authlib.decrypt_secret(row["mfa_secret"],SECRET),str(data.get("code",""))): self.throttle(db,"mfa-recovery:"+str(user["id"]),5,900); db.commit(); raise APIError(401,"Authenticator code is invalid")
            self.clear_throttle(db,"mfa-recovery:"+str(user["id"]))
            codes=authlib.recovery_codes(); db.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(user["id"],)); db.executemany("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)",[(user["id"],authlib.token_hash(c)) for c in codes]); self.security_event(db,"mfa_recovery_regenerated",user["id"]); db.commit(); self.send_json({"recovery_codes":codes}); return
        if path=="/api/auth/change-password" and method=="POST":
            row=db.execute("SELECT password_hash FROM users WHERE id=?",(user["id"],)).fetchone(); new=data.get("new_password","")
            if not pw_verify(str(data.get("current_password","")),row["password_hash"]): self.throttle(db,"password-change:"+str(user["id"]),5,900); self.security_event(db,"password_change",user["id"],False); db.commit(); raise APIError(401,"Current password is incorrect")
            self.clear_throttle(db,"password-change:"+str(user["id"]))
            if not authlib.valid_password(new) or new!=data.get("confirm_password"): raise ValueError("Choose a matching password with at least 6 characters")
            db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND kind='password_reset' AND used_at IS NULL",(user["id"],)); db.execute("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(pw_hash(new),user["id"])); db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND id<>? AND revoked_at IS NULL",(user["id"],user["_session_id"])); self.security_event(db,"password_changed",user["id"]); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/auth/sessions" and method=="GET":
            self.send_json({"sessions":rows(db.execute("SELECT id,created_at,last_seen_at,expires_at,ip_address,user_agent,CASE WHEN id=? THEN 1 ELSE 0 END current FROM auth_sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>=? ORDER BY last_seen_at DESC",(user["_session_id"],user["id"],int(time.time()))))}); return
        if path=="/api/auth/sessions/revoke-others" and method=="POST":
            count=db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND id<>? AND revoked_at IS NULL",(user["id"],user["_session_id"])).rowcount; self.security_event(db,"sessions_revoked",user["id"],True,{"count":count}); db.commit(); self.send_json({"ok":True,"revoked":count}); return
        if len(segments)==5 and segments[:4]==["api","auth","sessions","revoke"] and method=="POST":
            sid=int(segments[4]); count=db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND revoked_at IS NULL",(sid,user["id"])).rowcount
            if not count: raise APIError(404,"Session not found")
            self.security_event(db,"session_revoked",user["id"],True,{"session_id":sid}); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/auth/security-events" and method=="GET":
            self.send_json({"events":rows(db.execute("SELECT event,success,ip_address,user_agent,details,created_at FROM security_events WHERE user_id=? ORDER BY id DESC LIMIT 100",(user["id"],)))}); return
        if path=="/api/admin/security-events" and method=="GET":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            self.send_json({"events":rows(db.execute("SELECT e.id,e.user_id,u.email,e.event,e.success,e.ip_address,e.user_agent,e.details,e.created_at FROM security_events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 300"))}); return
        if path=="/api/admin/users" and method=="GET":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            search=str(q.get("q",[""])[0])[:120]; active=q.get("active",[""])[0]; sql="SELECT id,full_name,username,email,role,is_active,is_email_verified,email_verification_skipped,mfa_enabled,require_mfa,last_login_at,created_at FROM users WHERE 1=1"; args=[]
            if search: sql+=" AND (full_name LIKE ? OR username LIKE ? OR email LIKE ?)"; args.extend(["%"+search+"%"]*3)
            if active in ("0","1"): sql+=" AND is_active=?"; args.append(int(active))
            sql+=" ORDER BY created_at DESC LIMIT 500"; self.send_json({"users":rows(db.execute(sql,args))}); return
        if path=="/api/admin/users" and method=="POST":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            full_name=required(data,"full_name",120); username=required(data,"username",40).lower(); email=required(data,"email",254).lower(); password=data.get("password",""); role=valid_choice(data.get("role"),("admin","auditor","user"))
            if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,39}",username): raise ValueError("Invalid username")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,63}",email): raise ValueError("Enter a valid email address")
            if not authlib.valid_password(password): raise ValueError("Password must be 6–256 characters")
            org_id=data.get("organization_id"); org=db.execute("SELECT id FROM organizations WHERE id=?",(int(org_id),)).fetchone() if org_id else db.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
            if not org: raise APIError(400,"Create an organization before adding users")
            if db.execute("SELECT 1 FROM users WHERE email=? OR username=? COLLATE NOCASE",(email,username)).fetchone(): raise APIError(409,"Email or username is already in use")
            uid=db.execute("INSERT INTO users(email,password_hash,role,full_name,username,is_active,is_email_verified,require_mfa) VALUES(?,?,?,?,?,?,?,?)",(email,pw_hash(password),role,full_name,username,valid_bool(data.get("is_active",True),"is_active"),valid_bool(data.get("is_email_verified",True),"is_email_verified"),valid_bool(data.get("require_mfa",False),"require_mfa"))).lastrowid
            org_role={"admin":"admin","auditor":"analyst","user":"viewer"}[role]; db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,?)",(uid,org[0],org_role)); self.audit(db,user,"user.created","user",uid,{"role":role}); self.security_event(db,"admin_user_created",uid); db.commit(); self.send_json({"id":uid,"role":role},201); return
        if path=="/api/admin/users/invite" and method=="POST":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            full_name=required(data,"full_name",120); email=required(data,"email",254).lower(); role=valid_choice(data.get("role"),("admin","auditor","user")); username=str(data.get("username") or email.split("@")[0]).lower()[:40]
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,63}",email): raise ValueError("Enter a valid email address")
            if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,39}",username): raise ValueError("Invalid username")
            if not authlib.smtp_configured(): raise APIError(503,"SMTP email delivery is not configured")
            if db.execute("SELECT 1 FROM users WHERE email=? OR username=? COLLATE NOCASE",(email,username)).fetchone(): raise APIError(409,"Email or username is already in use")
            org_id=int(data.get("organization_id",0)); org=db.execute("SELECT id FROM organizations WHERE id=?",(org_id,)).fetchone()
            if not org: raise APIError(400,"Choose a valid organization")
            temp=authlib.token(); uid=db.execute("INSERT INTO users(email,password_hash,role,full_name,username,is_active,is_email_verified,require_mfa) VALUES(?,?,?,?,?,1,0,?)",(email,pw_hash(temp),role,full_name,username,valid_bool(data.get("require_mfa",False),"require_mfa"))).lastrowid
            db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,?)",(uid,org_id,{"admin":"admin","auditor":"analyst","user":"viewer"}[role])); raw=authlib.token(); db.execute("INSERT INTO auth_tokens(user_id,kind,token_hash,expires_at,metadata) VALUES(?,?,?,?,?)",(uid,"invitation",authlib.token_hash(raw),int(time.time())+172800,json.dumps({"organization_id":org_id})))
            url=os.environ.get("AUDIT_PUBLIC_URL","").rstrip("/"); text="You have been invited to Sentinel Audit. Use this one-time invitation code to set your password: "+raw+"\nIt expires in 48 hours."
            if url: text+="\n\nOpen: "+url+"/?invite="+quote(raw)
            try: authlib.send_email(email,"Sentinel Audit invitation",text)
            except Exception: db.rollback(); raise APIError(503,"Invitation email could not be sent. Check SMTP settings and retry.")
            self.audit(db,user,"user.invited","user",uid,{"role":role}); self.security_event(db,"user_invited",uid); db.commit(); self.send_json({"ok":True,"id":uid},201); return
        if path.startswith("/api/admin/users/"):
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            parts=segments; target_id=int(parts[3]) if len(parts)>3 and parts[3].isdigit() else 0; target=db.execute("SELECT * FROM users WHERE id=?",(target_id,)).fetchone() if target_id else None
            if not target: raise APIError(404,"User not found")
            action=parts[4] if len(parts)>4 else ""
            if len(parts)==4 and method=="PATCH":
                allowed={"full_name","username","email","role","is_active","is_email_verified","require_mfa"}; changes={k:data[k] for k in allowed if k in data}
                if "role" in changes: changes["role"]=valid_choice(changes["role"],("admin","auditor","user"))
                if "email" in changes:
                    changes["email"]=required(changes,"email",254).lower()
                    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,63}",changes["email"]): raise ValueError("Enter a valid email address")
                    if changes["email"]!=target["email"].lower() and "is_email_verified" not in changes: changes["is_email_verified"]=0
                if "username" in changes:
                    changes["username"]=required(changes,"username",40).lower()
                    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,39}",changes["username"]): raise ValueError("Invalid username")
                if "full_name" in changes: changes["full_name"]=required(changes,"full_name",120)
                if "is_active" in changes: changes["is_active"]=valid_bool(changes["is_active"],"is_active")
                if "is_email_verified" in changes: changes["is_email_verified"]=valid_bool(changes["is_email_verified"],"is_email_verified")
                if "require_mfa" in changes: changes["require_mfa"]=valid_bool(changes["require_mfa"],"require_mfa")
                if changes.get("is_active")==0 and target_id==user["id"]: raise APIError(400,"You cannot deactivate your own account")
                if target["role"]=="admin" and (changes.get("is_active")==0 or changes.get("role", "admin")!="admin") and db.execute("SELECT count(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0]<=1: raise APIError(409,"The last active administrator must remain active")
                if not changes: raise APIError(400,"No supported user fields were supplied")
                assignments=",".join(f"{k}=?" for k in changes); db.execute(f"UPDATE users SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?",(*changes.values(),target_id))
                if "role" in changes: db.execute("UPDATE memberships SET role=? WHERE user_id=?",({"admin":"admin","auditor":"analyst","user":"viewer"}[changes["role"]],target_id))
                email_changed="email" in changes and changes["email"]!=target["email"].lower()
                if changes.get("is_active")==0 or changes.get("is_email_verified")==0 or email_changed:
                    db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL",(target_id,))
                    db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND used_at IS NULL AND kind IN ('email_verify','password_reset','invitation')",(target_id,))
                self.audit(db,user,"user.updated","user",target_id,{"fields":sorted(changes)})
                if "is_active" in changes: self.security_event(db,"user_activated" if changes["is_active"] else "user_deactivated",target_id)
                if "role" in changes: self.security_event(db,"user_role_changed",target_id,True,{"role":changes["role"]})
                if "email" in changes and email_changed: self.security_event(db,"user_email_changed",target_id)
                if not any(key in changes for key in ("is_active","role","email")): self.security_event(db,"admin_user_updated",target_id)
                db.commit(); self.send_json({"ok":True}); return
            if len(parts)==4 and method=="DELETE":
                if target_id==user["id"]: raise APIError(400,"You cannot delete your own account")
                if target["role"]=="admin" and db.execute("SELECT count(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0]<=1: raise APIError(409,"The last active administrator cannot be deleted")
                db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL",(target_id,)); db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND used_at IS NULL",(target_id,)); db.execute("DELETE FROM memberships WHERE user_id=?",(target_id,)); db.execute("UPDATE users SET email=?,full_name='Deleted user',username='',password_hash=?,role='user',is_active=0,is_email_verified=0,email_verification_skipped=0,mfa_secret='',mfa_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?",(f"deleted-{target_id}-{secrets.token_hex(4)}@invalid.local",pw_hash(authlib.token()),target_id)); self.audit(db,user,"user.deleted","user",target_id); self.security_event(db,"admin_user_deleted",target_id); db.commit(); self.send_json({"ok":True}); return
            if action=="reset-mfa" and method=="POST":
                db.execute("UPDATE users SET mfa_enabled=0,mfa_secret='',updated_at=CURRENT_TIMESTAMP WHERE id=?",(target_id,)); db.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(target_id,)); db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL",(target_id,)); self.audit(db,user,"user.mfa_reset","user",target_id); self.security_event(db,"admin_mfa_reset",target_id); db.commit(); self.send_json({"ok":True}); return
            if action=="reset-password" and method=="POST":
                password=data.get("password","")
                if not authlib.valid_password(password): raise ValueError("Password must be 6–256 characters")
                db.execute("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(pw_hash(password),target_id)); db.execute("UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL",(target_id,)); db.execute("UPDATE auth_tokens SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND kind IN ('password_reset','invitation') AND used_at IS NULL",(target_id,)); self.audit(db,user,"user.password_reset","user",target_id); self.security_event(db,"admin_password_reset",target_id); db.commit(); self.send_json({"ok":True}); return
            raise APIError(405,"Unsupported user management action")
        if path=="/api/reset" and method=="POST":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            if data.get("confirmation")!="ERASE ALL SAVED ASSESSMENT DATA": raise APIError(400,"Type the exact confirmation phrase to erase saved assessment data")
            for job in db.execute("SELECT id FROM scan_jobs WHERE status IN ('queued','running')").fetchall():
                with SCAN_LOCK:
                    if job["id"] in SCAN_EVENTS: SCAN_EVENTS[job["id"]].set()
            db.execute("BEGIN IMMEDIATE")
            counts={}
            for table in ("evidence","findings","assessments","control_results","assets","scan_jobs","audit_log"):
                counts[table]=db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                db.execute(f"DELETE FROM {table}")
            self.audit(db,user,"workspace.data_reset","workspace",None,{"scope":"all_organizations_and_projects","deleted":counts})
            db.commit(); self.send_json({"ok":True,"deleted":counts,"preserved":["users","organizations","projects","templates","controls"]}); return
        if path=="/api/scan-jobs" and method=="POST":
            pid=int(data.get("project_id",0)); project_access=self.project(db,user,pid,True); kind=valid_choice(data.get("kind"),("local","network","android_device","android_adb")); target=""; authorized=False; public_authorized=False; device_payload=None; scanner_agent_id=None
            if db.execute("SELECT count(*) FROM scan_jobs WHERE status IN ('queued','running')").fetchone()[0]>=4: raise APIError(429,"The scan worker limit is reached; try again when an active scan finishes")
            requested_target=""
            if kind=="network":
                requested_target=required(data,"target",253); target=requested_target; authorized=data.get("authorized") is True; public_authorized=data.get("public_authorized") is True
                resolved_scope=assessments.validate_scope(target,authorized,public_authorized)
                if public_authorized: target=str(resolved_scope)
                else:
                    org_id=project_access["organization_id"]
                    agent=db.execute("SELECT id FROM scanner_agents WHERE organization_id=? AND revoked_at IS NULL AND julianday(last_seen_at)>=julianday('now','-120 seconds') ORDER BY last_seen_at DESC LIMIT 1",(org_id,)).fetchone()
                    if agent:
                        scanner_agent_id=agent["id"]
                    elif os.environ.get("AUDIT_REQUIRE_SCANNER_AGENT","0").lower() in ("1","true","yes"):
                        raise APIError(503,"No enrolled scanner agent is online for this organization. Start its agent on a computer inside the authorized private network, then retry.")
            elif kind=="android_device":
                if data.get("consent_confirmed") is not True: raise APIError(400,"Explicit on-device consent is required")
                if not self.secure_transport(): raise APIError(400,"Android device audits require HTTPS to protect the app inventory in transit")
                if not SECRET_CONFIGURED: raise APIError(503,"Configure a stable AUDIT_SECRET before storing encrypted Android app inventory")
                device_payload=android_device.validate_payload(data.get("device_audit"))
                target="Android device audit"
                authorized=True
            elif kind=="android_adb":
                if data.get("consent_confirmed") is not True: raise APIError(400,"Explicit authorization is required before auditing a paired Android phone")
                if not SECRET_CONFIGURED: raise APIError(503,"Configure a stable AUDIT_SECRET before storing encrypted Android app inventory")
                try: target=android_adb.validate_target(required(data,"target",32))
                except ValueError as exc: raise APIError(400,str(exc))
                authorized=True
            else:
                if data.get("consent_confirmed") is not True: raise APIError(400,"Explicit consent is required before assessing the Sentinel server computer")
                target="This server"; authorized=True
            job_id=uuid.uuid4().hex
            db.execute("INSERT INTO scan_jobs(id,project_id,requested_by,kind,target,authorized,public_authorized,status,message,scanner_agent_id) VALUES(?,?,?,?,?,?,?,'queued','Waiting for an assessment worker',?)",(job_id,pid,user["id"],kind,target,int(authorized),int(public_authorized),scanner_agent_id if kind=="network" else None))
            if kind=="local": self.audit(db,user,"scan.consent_authorized","assessment_consent",None,{"job_id":job_id,"scope":"Sentinel server computer","categories":["operating_system_and_security_settings","installed_software_inventory","endpoint_protection","firewall_and_network_services"],"read_only":True},pid)
            if kind=="android_device":
                sealed_payload=authlib.encrypt_secret(json.dumps(device_payload,separators=(",",":")),SECRET)
                db.execute("INSERT INTO scan_job_inputs(job_id,payload) VALUES(?,?)",(job_id,sealed_payload))
                self.audit(db,user,"scan.consent_authorized","assessment_consent",None,{"job_id":job_id,"scope":"User-authorized Android device","categories":["device model and Android version","security patch date","supported security settings","launcher-visible app names and versions"],"read_only":True,"transport":"HTTPS required by Android client"},pid)
            if kind=="android_adb": self.audit(db,user,"scan.consent_authorized","assessment_consent",None,{"job_id":job_id,"scope":"One user-authorized Android phone paired over Wireless debugging","target":target,"categories":["device model and Android version","security patch date","ADB and developer setting status","storage encryption system property","third-party package names and versions"],"read_only":True,"app_data_accessed":False},pid)
            self.audit(db,user,"scan.queued","scan_job",None,{"job_id":job_id,"kind":kind,"target":target,**({"requested_target":requested_target} if requested_target and requested_target!=target else {}),**({"scanner_agent_id":scanner_agent_id} if kind=="network" and scanner_agent_id else {})},pid); db.commit()
            if kind!="network" or not scanner_agent_id: threading.Thread(target=run_scan_job,args=(job_id,),daemon=True).start()
            self.send_json({"job_id":job_id,"status":"queued","target":target,**({"scanner_agent_id":scanner_agent_id} if kind=="network" and scanner_agent_id else {})},202); return
        if path=="/api/scan-jobs" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); project=self.project(db,user,pid); sql="SELECT id,project_id,requested_by,kind,target,status,progress,message,error,result,retry_of,created_at,updated_at FROM scan_jobs WHERE project_id=?"; args=[pid]
            if project["organization_role"]!="admin" and user.get("role")!="admin": sql+=" AND requested_by=?"; args.append(user["id"])
            jobs=rows(db.execute(sql+" ORDER BY created_at DESC LIMIT 50",args))
            for item in jobs:
                try: item["result"]=json.loads(item["result"]) if item["result"] else None
                except (TypeError,ValueError): item["result"]=None
            self.send_json({"jobs":jobs}); return
        if len(segments)==3 and segments[:2]==["api","scan-jobs"] and method in ("GET","DELETE"):
            job=db.execute("SELECT * FROM scan_jobs WHERE id=?",(segments[2],)).fetchone()
            if not job: raise APIError(404,"Scan job not found")
            project=self.project(db,user,job["project_id"],method=="DELETE")
            if project["organization_role"]!="admin" and user.get("role")!="admin" and job["requested_by"]!=user["id"]: raise APIError(404,"Scan job not found")
            if method=="DELETE":
                if job["status"] in ("completed","failed","cancelled"): raise APIError(409,"Only queued or running scans can be cancelled")
                db.execute("UPDATE scan_jobs SET cancel_requested=1,message='Cancellation requested',updated_at=CURRENT_TIMESTAMP WHERE id=?",(job["id"],)); db.commit()
                with SCAN_LOCK:
                    if job["id"] in SCAN_EVENTS: SCAN_EVENTS[job["id"]].set()
                self.send_json({"ok":True,"status":"cancelling"},202); return
            item=dict(job); item["result"]=json.loads(item["result"]); item.pop("cancel_requested",None); self.send_json({"job":item}); return
        if len(segments)==4 and segments[:2]==["api","scan-jobs"] and segments[3]=="retry" and method=="POST":
            old=db.execute("SELECT * FROM scan_jobs WHERE id=?",(segments[2],)).fetchone()
            if not old: raise APIError(404,"Scan job not found")
            self.project(db,user,old["project_id"],True)
            if old["status"] not in ("failed","cancelled"): raise APIError(409,"Only failed or cancelled scans can be retried")
            if old["kind"]=="network": assessments.validate_scope(old["target"],bool(old["authorized"]),bool(old["public_authorized"]))
            job_id=uuid.uuid4().hex; db.execute("INSERT INTO scan_jobs(id,project_id,requested_by,kind,target,authorized,public_authorized,status,message,retry_of) VALUES(?,?,?,?,?,?,?,'queued','Retry queued',?)",(job_id,old["project_id"],user["id"],old["kind"],old["target"],old["authorized"],old["public_authorized"],old["id"]))
            if old["kind"]=="android_device":
                source=db.execute("SELECT payload FROM scan_job_inputs WHERE job_id=?",(old["id"],)).fetchone()
                if not source: raise APIError(409,"The Android audit payload is no longer available for retry")
                db.execute("INSERT INTO scan_job_inputs(job_id,payload) VALUES(?,?)",(job_id,source["payload"]))
            self.audit(db,user,"scan.retried","scan_job",None,{"job_id":job_id,"retry_of":old["id"]},old["project_id"]); db.commit(); threading.Thread(target=run_scan_job,args=(job_id,),daemon=True).start(); self.send_json({"job_id":job_id,"status":"queued"},202); return
        if path=="/api/scanner-agents" and method=="GET":
            requested=q.get("organization_id",[""])[0]
            if requested: org_id=int(requested); self.org_admin(db,user,org_id)
            elif user.get("role")=="admin": org_id=None
            else: raise APIError(400,"Organization ID is required")
            sql="SELECT id,organization_id,name,created_at,last_seen_at,revoked_at FROM scanner_agents"; args=[]
            if org_id is not None: sql+=" WHERE organization_id=?"; args.append(org_id)
            self.send_json({"agents":rows(db.execute(sql+" ORDER BY created_at DESC",args))}); return
        if path=="/api/scanner-agents" and method=="POST":
            org_id=int(data.get("organization_id",0)); self.org_admin(db,user,org_id); name=required(data,"name",100)
            agent_id=uuid.uuid4().hex; raw_token="sag_"+secrets.token_urlsafe(36); digest=hashlib.sha256(raw_token.encode()).hexdigest()
            db.execute("INSERT INTO scanner_agents(id,organization_id,name,token_hash,created_by) VALUES(?,?,?,?,?)",(agent_id,org_id,name,digest,user["id"]))
            self.audit(db,user,"scanner_agent.enrolled","scanner_agent",None,{"agent_id":agent_id,"name":name,"organization_id":org_id}); db.commit()
            self.send_json({"id":agent_id,"name":name,"token":raw_token,"token_shown_once":True},201); return
        agent_route=re.fullmatch(r"/api/scanner-agents/([a-f0-9]{32})",path)
        if agent_route and method=="DELETE":
            agent=db.execute("SELECT * FROM scanner_agents WHERE id=?",(agent_route.group(1),)).fetchone()
            if not agent: raise APIError(404,"Scanner agent not found")
            self.org_admin(db,user,agent["organization_id"])
            db.execute("UPDATE scanner_agents SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND revoked_at IS NULL",(agent["id"],)); db.execute("UPDATE scan_jobs SET status='failed',message='Assigned scanner agent was revoked',error='The organization scanner agent was revoked before completing the assessment',updated_at=CURRENT_TIMESTAMP WHERE scanner_agent_id=? AND status IN ('queued','running')",(agent["id"],)); self.audit(db,user,"scanner_agent.revoked","scanner_agent",None,{"agent_id":agent["id"],"organization_id":agent["organization_id"]}); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/membership-requests" and method=="GET":
            requested_org=q.get("organization_id",[""])[0]
            if requested_org:
                oid=int(requested_org); self.org_admin(db,user,oid)
                items=rows(db.execute("SELECT id,organization_id,email,full_name,status,requested_at FROM membership_requests WHERE organization_id=? AND status='pending' ORDER BY requested_at",(oid,)))
            elif user.get("role")=="admin":
                items=rows(db.execute("SELECT r.id,r.organization_id,o.name organization,r.email,r.full_name,r.status,r.requested_at FROM membership_requests r JOIN organizations o ON o.id=r.organization_id WHERE r.status='pending' ORDER BY r.requested_at"))
            else: raise APIError(400,"Organization ID is required")
            self.send_json({"requests":items}); return
        if len(segments)==4 and segments[:2]==["api","membership-requests"] and segments[3]=="decision" and method=="POST":
            try: request_id=int(segments[2])
            except ValueError: raise APIError(404,"Account request not found")
            request=db.execute("SELECT * FROM membership_requests WHERE id=? AND status='pending'",(request_id,)).fetchone()
            if not request: raise APIError(404,"Pending account request not found")
            self.org_admin(db,user,request["organization_id"]); decision=valid_choice(data.get("decision"),("approve","reject"))
            if decision=="approve":
                if db.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE",(request["email"],)).fetchone(): raise APIError(409,"An account with this email already exists")
                base=re.sub(r"[^a-z0-9_.-]","-",request["email"].split("@",1)[0].lower()).strip("._-")[:32] or "member"; username=base
                while db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(username,)).fetchone(): username=base[:25]+"-"+secrets.token_hex(3)
                cur=db.execute("INSERT INTO users(email,password_hash,role,full_name,username,is_email_verified,email_verification_skipped) VALUES(?,?,'member',?,?,1,1)",(request["email"],request["password_hash"],request["full_name"],username)); uid=cur.lastrowid
                db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,'analyst')",(uid,request["organization_id"]))
            db.execute("UPDATE membership_requests SET status=?,password_hash='',reviewed_at=CURRENT_TIMESTAMP,reviewed_by=? WHERE id=?",("approved" if decision=="approve" else "rejected",user["id"],request_id))
            self.audit(db,user,"membership_request."+decision,"membership_request",request_id,{"email":request["email"],"organization_id":request["organization_id"]}); self.security_event(db,"membership_request_"+decision,uid if decision=="approve" else None,True,{"organization_id":request["organization_id"]}); db.commit(); self.send_json({"ok":True,"decision":decision,"user_id":uid if decision=="approve" else None}); return
        if path=="/api/organizations" and method=="GET":
            orgs=rows(db.execute("SELECT * FROM organizations ORDER BY name") if user.get("role")=="admin" else db.execute("SELECT o.* FROM organizations o JOIN memberships m ON m.organization_id=o.id WHERE m.user_id=? ORDER BY o.name",(user["id"],)))
            self.send_json({"organizations":orgs}); return
        if path=="/api/organizations" and method=="POST":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            name=required(data,"name",120); cur=db.execute("INSERT INTO organizations(name,industry) VALUES(?,?)",(name,str(data.get("industry",""))[:120])); oid=cur.lastrowid; db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,'admin')",(user["id"],oid)); self.audit(db,user,"organization.created","organization",oid); db.commit(); self.send_json({"id":oid,"name":name},201); return
        if path=="/api/projects" and method=="GET":
            projects=rows(db.execute("SELECT p.*,o.name organization,'admin' organization_role FROM projects p JOIN organizations o ON o.id=p.organization_id ORDER BY p.id") if user.get("role")=="admin" else db.execute("SELECT p.*,o.name organization,m.role organization_role FROM projects p JOIN organizations o ON o.id=p.organization_id JOIN memberships m ON m.organization_id=o.id WHERE m.user_id=? ORDER BY p.id",(user["id"],)))
            self.send_json({"projects":projects}); return
        if path=="/api/projects" and method=="POST":
            oid=int(data.get("organization_id",0)); org=self.org(db,user,oid); self.org_admin(db,user,oid); name=required(data,"name",120); cur=db.execute("INSERT INTO projects(organization_id,name,description) VALUES(?,?,?)",(oid,name,str(data.get("description",""))[:2000])); self.audit(db,user,"project.created","project",cur.lastrowid); db.commit(); self.send_json({"id":cur.lastrowid,"organization":org["name"],"name":name},201); return
        if path=="/api/users" and method=="POST":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            email=required(data,"email",254).lower()
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email): raise ValueError("Enter a valid email address")
            password=data.get("password","")
            if not authlib.valid_password(password): raise ValueError("Password must be 6–256 characters")
            oid=int(data.get("organization_id",0)); self.org_admin(db,user,oid); role=valid_choice(data.get("organization_role","viewer"),("admin","analyst","viewer"))
            try: cur=db.execute("INSERT INTO users(email,password_hash,role) VALUES(?,?,'member')",(email,pw_hash(password)))
            except Exception as e:
                if "UNIQUE" in str(e): raise APIError(409,"An account with that email already exists")
                raise
            db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,?)",(cur.lastrowid,oid,role)); self.audit(db,user,"user.created","user",cur.lastrowid,{"email":email,"organization_role":role}); db.commit(); self.send_json({"id":cur.lastrowid,"email":email,"role":role},201); return
        if path=="/api/templates" and method=="GET": self.send_json({"templates":rows(db.execute("SELECT * FROM templates ORDER BY id"))}); return
        if path=="/api/templates" and method=="POST":
            if user["role"]!="admin": raise APIError(403,"Administrator access required")
            name=required(data,"name",120); checks=data.get("checks",[])
            if not isinstance(checks,list) or len(checks)>50 or any(not isinstance(x,str) or len(x)>80 for x in checks): raise ValueError("Checks must be a list of up to 50 short strings")
            cur=db.execute("INSERT INTO templates(name,description,checks) VALUES(?,?,?)",(name,str(data.get("description",""))[:2000],json.dumps(checks))); self.audit(db,user,"template.created","template",cur.lastrowid); db.commit(); self.send_json({"id":cur.lastrowid,"name":name},201); return
        if path=="/api/controls" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); self.project(db,user,pid); self.send_json({"controls":grc.evaluate(db,pid)}); return
        if path=="/api/controls" and method=="POST":
            pid=int(data.get("project_id",0)); p=self.project(db,user,pid); self.org_admin(db,user,p["organization_id"])
            framework=required(data,"framework",80); key=required(data,"control_key",80); title=required(data,"title",240)
            try: cur=db.execute("INSERT INTO controls(framework,control_key,title,description) VALUES(?,?,?,?)",(framework,key,title,str(data.get("description",""))[:2000]))
            except Exception as e:
                if "UNIQUE" in str(e): raise APIError(409,"That framework control already exists")
                raise
            self.audit(db,user,"control.created","control",cur.lastrowid,{"framework":framework,"key":key},pid); db.commit(); self.send_json({"id":cur.lastrowid},201); return
        if path=="/api/controls" and method=="PATCH":
            pid=int(data.get("project_id",0)); self.project(db,user,pid,True); cid=int(data.get("control_id",0)); status=data.get("status");
            if status not in ("implemented","partial","not_implemented","not_applicable","not_assessed"): raise ValueError("Invalid control status")
            if not db.execute("SELECT id FROM controls WHERE id=?",(cid,)).fetchone(): raise APIError(404,"Control not found")
            db.execute("INSERT INTO control_results(project_id,control_id,status,evidence,assessor,updated_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(project_id,control_id) DO UPDATE SET status=excluded.status,evidence=excluded.evidence,assessor=excluded.assessor,updated_at=CURRENT_TIMESTAMP",(pid,cid,status,str(data.get("evidence",""))[:4000],user["email"])); self.audit(db,user,"control.updated","control",cid,{"status":status},pid); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/assets" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); self.project(db,user,pid); self.send_json({"assets":rows(db.execute("SELECT * FROM assets WHERE project_id=? ORDER BY name",(pid,)))}); return
        if path=="/api/assets" and method=="POST":
            pid=int(data.get("project_id",0)); self.project(db,user,pid,True); name=required(data,"name",160); addr=str(data.get("address",""))[:253]; cur=db.execute("INSERT INTO assets(project_id,name,hostname,address,asset_type,criticality,owner,notes) VALUES(?,?,?,?,?,?,?,?)",(pid,name,str(data.get("hostname",""))[:253],addr,str(data.get("asset_type","endpoint"))[:40],valid_choice(data.get("criticality","medium"),("low","medium","high","critical")),str(data.get("owner",""))[:160],str(data.get("notes",""))[:2000])); self.audit(db,user,"asset.created","asset",cur.lastrowid,project_id=pid); db.commit(); self.send_json({"id":cur.lastrowid,"name":name},201); return
        if len(segments)==3 and segments[:2]==["api","assets"] and method in ("PATCH","DELETE"):
            aid=int(segments[2]); asset=db.execute("SELECT * FROM assets WHERE id=?",(aid,)).fetchone()
            if not asset: raise APIError(404,"Asset not found")
            self.project(db,user,asset["project_id"],True)
            if method=="DELETE":
                if db.execute("SELECT 1 FROM findings WHERE asset_id=? LIMIT 1",(aid,)).fetchone(): raise APIError(409,"This asset has findings attached; retain it to preserve assessment history")
                db.execute("DELETE FROM assets WHERE id=?",(aid,)); self.audit(db,user,"asset.deleted","asset",aid,project_id=asset["project_id"]); db.commit(); self.send_json({"ok":True}); return
            allowed={"name":"name","hostname":"hostname","address":"address","asset_type":"asset_type","criticality":"criticality","owner":"owner","notes":"notes"}; changes={}
            for key,col in allowed.items():
                if key in data:
                    value=valid_choice(data[key],("low","medium","high","critical")) if key=="criticality" else str(data[key])[:(160 if key=="name" else 2000)]
                    if key=="name" and not value.strip(): raise ValueError("Asset name cannot be empty")
                    changes[col]=value
            if not changes: raise ValueError("No editable asset fields supplied")
            expr=",".join(f"{key}=?" for key in changes); db.execute(f"UPDATE assets SET {expr} WHERE id=?",[*changes.values(),aid]); self.audit(db,user,"asset.updated","asset",aid,changes,asset["project_id"]); db.commit(); self.send_json({"ok":True}); return
        if path=="/api/assessments/local" and method=="POST":
            if data.get("consent_confirmed") is not True: raise APIError(400,"Explicit consent is required before assessing the Sentinel server computer")
            pid=int(data.get("project_id",0)); self.project(db,user,pid,True); self.audit(db,user,"scan.consent_authorized","assessment_consent",None,{"scope":"Sentinel server computer","categories":["operating_system_and_security_settings","installed_software_inventory","endpoint_protection","firewall_and_network_services"],"read_only":True,"method":"direct_assessment_api"},pid); db.commit(); result=assessments.local_assessment(); asset_name=result["facts"].get("hostname","Local system"); host_addr="127.0.0.1"
            existing=db.execute("SELECT id FROM assets WHERE project_id=? AND address=? ORDER BY id LIMIT 1",(pid,host_addr)).fetchone()
            if existing:
                aid=existing[0]; db.execute("UPDATE assets SET name=?,hostname=?,asset_type='endpoint',criticality='high' WHERE id=?",(asset_name,asset_name,aid))
            else: aid=db.execute("INSERT INTO assets(project_id,name,hostname,address,asset_type,criticality) VALUES(?,?,?,?,'endpoint','high') RETURNING id",(pid,asset_name,asset_name,host_addr)).fetchone()[0]
            self.save_assessment(db,user,pid,aid,"local",result); self.send_json({"result":result,"asset_id":aid}); return
        if path=="/api/assessments/network" and method=="POST":
            pid=int(data.get("project_id",0)); self.project(db,user,pid,True); result=assessments.network_assessment(str(data.get("target","")),data.get("authorized"),data.get("public_authorized",False)); self.save_assessment(db,user,pid,None,"network",result)
            for host in result["hosts"]:
                existing=db.execute("SELECT id FROM assets WHERE project_id=? AND address=? ORDER BY id LIMIT 1",(pid,host["address"])).fetchone()
                if existing: db.execute("UPDATE assets SET hostname=? WHERE id=?",(host["hostname"],existing[0]))
                else: db.execute("INSERT INTO assets(project_id,name,hostname,address,asset_type) VALUES(?,?,?,?,?)",(pid,host["hostname"] or host["address"],host["hostname"],host["address"],"network"))
            db.commit(); self.send_json({"result":result}); return
        if path=="/api/findings" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); project=self.project(db,user,pid); sql="SELECT f.*,a.name asset_name,a.criticality asset_criticality FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE f.project_id=?"; args=[pid]
            if project["organization_role"]!="admin" and user.get("role")!="admin": sql+=" AND f.assessment_id IN (SELECT id FROM assessments WHERE project_id=? AND authorized_by=?)"; args.extend((pid,user["id"]))
            if q.get("assessment_id"):
                try: assessment_id=int(q["assessment_id"][0])
                except (TypeError,ValueError): raise APIError(400,"Assessment ID must be a positive integer")
                if assessment_id<1: raise APIError(400,"Assessment ID must be a positive integer")
                if not db.execute("SELECT 1 FROM assessments WHERE id=? AND project_id=?",(assessment_id,pid)).fetchone(): raise APIError(404,"Assessment not found in this project")
                sql+=" AND f.assessment_id=?"; args.append(assessment_id)
            for key in ("severity","status","category"):
                if q.get(key) and not (key=="status" and q[key][0]=="active"): sql+=f" AND f.{key}=?"; args.append(q[key][0])
            if q.get("q"): sql+=" AND (f.title LIKE ? OR f.description LIKE ? OR f.cve LIKE ?)"; args += ["%"+q["q"][0][:100]+"%"]*3
            if q.get("status",[""])[0]=="active": sql+=" AND f.status NOT IN ('closed','resolved','accepted','false_positive')"
            sql+=" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,updated_at DESC"
            result=rows(db.execute(sql,args))
            for f in result:
                f["evidence"]=json.loads(f["evidence"]); f["control_ids"]=json.loads(f["control_ids"])
                computed=risk.calculate_finding_risk(f, {"criticality": f.get("asset_criticality")})
                f.update({k:computed[k] for k in ("risk","risk_score","risk_band","priority")})
            self.send_json({"findings":result}); return
        if len(segments)==3 and segments[:2]==["api","findings"] and method=="PATCH":
            fid=int(segments[2]); f=db.execute("SELECT * FROM findings WHERE id=?",(fid,)).fetchone()
            if not f: raise APIError(404,"Finding not found")
            project=self.project(db,user,f["project_id"],True)
            if project["organization_role"]!="admin" and user.get("role")!="admin": self.assessment_access(db,user,f["project_id"],f["assessment_id"])
            changes={}
            if "status" in data:
                # Keep legacy workflow values writable for existing records and API clients.
                next_status=valid_choice(data["status"],("open","remediation","retest","closed","accepted","false_positive","in_progress","resolved")); current=f["status"]
                transitions={"open":{"remediation","in_progress","accepted","false_positive"},"remediation":{"retest","open","in_progress"},"retest":{"remediation"},"closed":{"remediation"},"in_progress":{"remediation","retest","accepted","false_positive"},"resolved":{"remediation","closed"},"accepted":{"open","remediation"},"false_positive":{"open"}}
                if next_status=="closed": raise APIError(400,"A finding can be closed only by submitting a passing retest with evidence")
                if next_status!=current and next_status not in transitions.get(current,set()): raise APIError(409,f"Invalid finding lifecycle transition: {current} → {next_status}")
                changes["status"]=next_status
            if "severity" in data: changes["severity"]=valid_choice(data["severity"],tuple(risk.SEVERITY_SCORE))
            for key,low,high in (("likelihood",1,5),("impact",0,10)):
                if key in data:
                    value=data[key]
                    if isinstance(value,bool) or not isinstance(value,int) or not low<=value<=high: raise ValueError(f"{key.title()} must be an integer from {low} to {high}")
                    changes[key]=value
            if "assignee" in data: changes["assignee"]=str(data["assignee"])[:160]
            if "due_date" in data:
                due=str(data["due_date"])[:20]
                try: datetime.date.fromisoformat(due) if due else None
                except ValueError: raise ValueError("Due date must use YYYY-MM-DD")
                changes["due_date"]=due or None
            if not changes: raise ValueError("No editable fields supplied")
            if "severity" in changes and "impact" not in changes: changes["impact"]=risk.SEVERITY_SCORE[changes["severity"]]
            if any(k in changes for k in ("severity","likelihood","impact")):
                asset=db.execute("SELECT criticality FROM assets WHERE id=?",(f["asset_id"],)).fetchone() if f["asset_id"] else None
                rs=risk.score(changes.get("severity",f["severity"]),changes.get("likelihood",f["likelihood"]),changes.get("impact",f["impact"]),asset_criticality=asset["criticality"] if asset else "medium",cvss_score=f["cvss"]); changes["risk_score"]=rs["score"]
            changes["updated_at"]="CURRENT_TIMESTAMP"; assignments=",".join(f"{k}=?" for k in changes if k!="updated_at"); vals=[v for k,v in changes.items() if k!="updated_at"]+[fid]
            db.execute(f"UPDATE findings SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?",vals); self.audit(db,user,"finding.updated","finding",fid,changes,f["project_id"]); db.commit(); self.send_json({"ok":True}); return
        if len(segments)==3 and segments[:2]==["api","findings"] and method=="GET":
            fid=int(segments[2]); f=db.execute("SELECT f.*,a.name asset_name,a.criticality asset_criticality FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE f.id=?",(fid,)).fetchone()
            if not f: raise APIError(404,"Finding not found")
            project=self.project(db,user,f["project_id"])
            if project["organization_role"]!="admin" and user.get("role")!="admin": self.assessment_access(db,user,f["project_id"],f["assessment_id"])
            item=dict(f); item["evidence"]=json.loads(item["evidence"]); item["control_ids"]=json.loads(item["control_ids"])
            item["evidence_records"]=[dict(e,content=json.loads(e["content"])) for e in db.execute("SELECT id,source,content,verified,collected_at FROM evidence WHERE finding_id=? ORDER BY id",(fid,))]
            item.update(risk.calculate_finding_risk(item,{"criticality":item.get("asset_criticality")})); self.send_json({"finding":item}); return
        if len(segments)==4 and segments[:2]==["api","findings"] and segments[3]=="retest" and method=="POST":
            fid=int(segments[2]); finding=db.execute("SELECT * FROM findings WHERE id=?",(fid,)).fetchone()
            if not finding: raise APIError(404,"Finding not found")
            project=self.project(db,user,finding["project_id"],True)
            if project["organization_role"]!="admin" and user.get("role")!="admin": self.assessment_access(db,user,finding["project_id"],finding["assessment_id"])
            if finding["status"]!="retest": raise APIError(409,"Move the finding to Retest before recording retest evidence")
            passed=data.get("passed");
            if not isinstance(passed,bool): raise ValueError("Retest outcome must be true or false")
            note=required(data,"evidence",4000); source=required(data,"source",120); assessment_id=data.get("assessment_id")
            if assessment_id is not None: self.assessment_access(db,user,finding["project_id"],int(assessment_id))
            payload={"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source":source,"collector":"assessor-retest","assessment_id":assessment_id,"passed":passed,"notes":note}
            db.execute("INSERT INTO evidence(finding_id,source,content,verified) VALUES(?,?,?,?)",(fid,"retest",json.dumps(payload),int(passed)))
            next_status="closed" if passed else "remediation"; db.execute("UPDATE findings SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(next_status,fid)); self.audit(db,user,"finding.retest_"+("passed" if passed else "failed"),"finding",fid,payload,finding["project_id"]); db.commit(); self.send_json({"ok":True,"status":next_status,"evidence":payload}); return
        if path=="/api/assessments" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); project=self.project(db,user,pid); query="SELECT * FROM assessments WHERE project_id=?"; args=[pid]
            if project["organization_role"]!="admin" and user.get("role")!="admin": query+=" AND authorized_by=?"; args.append(user["id"])
            items=rows(db.execute(query+" ORDER BY completed_at DESC LIMIT 100",args))
            for a in items:
                a["summary"]=json.loads(a["summary"])
                if a.get("kind")=="android_device": a["summary"]=android_device.restore_inventory(a["summary"],SECRET)
            self.send_json({"assessments":items}); return
        if path=="/api/compare" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); project=self.project(db,user,pid); a,b=[int(x) for x in q.get("ids",["0,0"])[0].split(",")[:2]]; sql="SELECT * FROM assessments WHERE project_id=? AND id IN (?,?)"; args=[pid,a,b]
            if project["organization_role"]!="admin" and user.get("role")!="admin": sql+=" AND authorized_by=?"; args.append(user["id"])
            pair=rows(db.execute(sql+" ORDER BY completed_at",args))
            if len(pair)!=2: raise APIError(404,"Two assessments in this project are required")
            for x in pair:
                x["summary"]=json.loads(x["summary"])
                if x.get("kind")=="android_device": x["summary"]=android_device.restore_inventory(x["summary"],SECRET)
            self.send_json({"earlier":pair[0],"later":pair[1]}); return
        if path=="/api/dashboard" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); project=self.project(db,user,pid); own_filter="" if project["organization_role"]=="admin" or user.get("role")=="admin" else " AND f.assessment_id IN (SELECT id FROM assessments WHERE authorized_by=?)"; args=(pid,) if not own_filter else (pid,user["id"])
            open_rows=rows(db.execute("SELECT f.*,a.criticality asset_criticality FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE f.project_id=? AND f.status NOT IN ('closed','resolved','accepted','false_positive')"+own_filter,args))
            counts={s:sum(1 for f in open_rows if f.get("severity")==s) for s in risk.SEVERITY_SCORE}
            risk_items=[{"likelihood":f.get("likelihood",3),"impact":f.get("impact",5)} for f in open_rows]
            assessment_sql="SELECT count(*) FROM assessments WHERE project_id=?"+("" if not own_filter else " AND authorized_by=?"); recent_sql="SELECT action,entity,details,created_at FROM audit_log WHERE project_id=?"+("" if not own_filter else " AND user_id=?")+" ORDER BY id DESC LIMIT 8"
            self.send_json({"assets":db.execute("SELECT count(*) FROM assets WHERE project_id=?",(pid,)).fetchone()[0],"findings":len(open_rows),"severity":counts,"risk_matrix":risk.matrix(risk_items),"risk_matrix_bands":risk.matrix_risk_bands(),"assessments":db.execute(assessment_sql,args).fetchone()[0],"recent":rows(db.execute(recent_sql,args))}); return
        if path=="/api/audit" and method=="GET":
            pid=int(q.get("project_id",[0])[0]); self.project(db,user,pid); items=rows(db.execute("SELECT l.*,u.email FROM audit_log l LEFT JOIN users u ON u.id=l.user_id WHERE l.project_id=? ORDER BY id DESC LIMIT 200",(pid,)))
            for x in items:x["details"]=json.loads(x["details"])
            self.send_json({"events":items}); return
        if path in ("/api/reports/json","/api/reports/pdf","/api/reports/html") and method=="GET":
            pid=int(q.get("project_id",[0])[0]); self.project(db,user,pid); mode=valid_choice(q.get("type",["technical"])[0],("technical","executive"))
            assessment_id=None
            project=self.project(db,user,pid)
            if "assessment_id" in q:
                try: assessment_id=int(q["assessment_id"][0])
                except (TypeError,ValueError): raise APIError(400,"Assessment ID must be a positive integer")
                if assessment_id<1: raise APIError(400,"Assessment ID must be a positive integer")
                owner=db.execute("SELECT authorized_by FROM assessments WHERE id=? AND project_id=?",(assessment_id,pid)).fetchone()
                if not owner or (project["organization_role"]!="admin" and user.get("role")!="admin" and owner["authorized_by"]!=user["id"]): raise APIError(404,"Assessment not found in this project")
            elif project["organization_role"]!="admin" and user.get("role")!="admin": raise APIError(403,"Members can download reports only for assessments they started")
            report=reports.collect(db,pid,mode,assessment_id)
            if path.endswith("json"):
                payload=reports.json_bytes(report); kind="application/json"; ext="json"
            elif path.endswith("html"):
                payload=reports.html_bytes(report); kind="text/html; charset=utf-8"; ext="html"
            else:
                payload=reports.pdf_bytes(report); kind="application/pdf"; ext="pdf"
            filename=f"security-{mode}-assessment-{assessment_id}.{ext}" if assessment_id is not None else f"security-{mode}-project-report.{ext}"
            self.send_response(200); self.send_header("Content-Type",kind); self.send_header("Content-Disposition",f"attachment; filename={filename}"); self.send_header("Content-Length",str(len(payload))); self.send_header("Cache-Control","no-store"); self.cors_headers(); self.end_headers(); self.wfile.write(payload); self.audit(db,user,"report.generated","assessment" if assessment_id is not None else "project",assessment_id if assessment_id is not None else pid,{"type":mode,"assessment_id":assessment_id},pid); db.commit(); return
        raise APIError(404,"API route not found")
    def save_assessment(self,db,user,pid,aid,kind,result):
        persist_assessment(db,user,pid,aid,kind,result)

def persist_assessment(db,user,pid,aid,kind,result):
    cur=db.execute("INSERT INTO assessments(project_id,asset_id,kind,summary,authorized_by) VALUES(?,?,?,?,?)",(pid,aid,kind,json.dumps(result),user["id"])); assessment_id=cur.lastrowid
    for finding in result.get("findings",[]):
        evidence=dict(finding.get("evidence",{})); evidence.setdefault("collected_at",datetime.datetime.now(datetime.timezone.utc).isoformat()); evidence.setdefault("collector",f"{kind} assessment engine"); evidence.setdefault("assessment_id",assessment_id)
        asset=db.execute("SELECT criticality FROM assets WHERE id=?",(aid,)).fetchone() if aid else None
        rs=risk.score(finding["severity"],finding.get("likelihood",3),finding.get("impact"),asset_criticality=asset["criticality"] if asset else "medium",cvss_score=finding.get("cvss")); control_ids=grc.mapped_control_ids(db,finding.get("category","configuration"))
        final_risk_score = rs["score"]
        cur_finding=db.execute("INSERT INTO findings(project_id,assessment_id,asset_id,title,category,severity,likelihood,impact,risk_score,description,evidence,verified,cve,cvss,control_ids,remediation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(pid,assessment_id,aid,finding["title"],finding.get("category","configuration"),finding["severity"],finding.get("likelihood",3),finding.get("impact",rs["impact"]),final_risk_score,finding.get("description",""),json.dumps(evidence),int(finding.get("verified",False)),finding.get("cve",""),finding.get("cvss"),json.dumps(control_ids),finding.get("remediation","")))
        fid=cur_finding.lastrowid
        corr_ev=evidence.get("correlated_evidence")
        if corr_ev and isinstance(corr_ev,list):
            for sub_ev in corr_ev:
                sub_dict=dict(sub_ev) if isinstance(sub_ev,dict) else {"details":str(sub_ev)}
                sub_dict.setdefault("collected_at",evidence.get("collected_at"))
                sub_dict.setdefault("collector",evidence.get("collector"))
                sub_dict.setdefault("assessment_id",assessment_id)
                db.execute("INSERT INTO evidence(finding_id,source,content,verified) VALUES(?,?,?,?)",(fid,str(sub_dict.get("source",kind+" assessment engine")),json.dumps(sub_dict),int(sub_dict.get("verified",finding.get("verified",False)))))
        else:
            db.execute("INSERT INTO evidence(finding_id,source,content,verified) VALUES(?,?,?,?)",(fid,str(evidence.get("source",kind+" assessment engine")),json.dumps(evidence),int(finding.get("verified",False))))
    db.execute("INSERT INTO audit_log(user_id,project_id,action,entity,entity_id,details) VALUES(?,?,?,?,?,?)",(user["id"],pid,"assessment.completed","assessment",assessment_id,json.dumps({"kind":kind,"findings":len(result.get("findings",[])),"raw_observations":len(result.get("raw_findings",result.get("findings",[])))}))); db.commit(); return assessment_id

def run_scan_job(job_id):
    event=threading.Event()
    with SCAN_LOCK: SCAN_EVENTS[job_id]=event
    db=connect()
    try:
        job=db.execute("SELECT * FROM scan_jobs WHERE id=?",(job_id,)).fetchone()
        if not job: return
        if job["cancel_requested"]: event.set()
        db.execute("UPDATE scan_jobs SET status='running',progress=0,message='Starting assessment',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='queued'",(job_id,)); db.commit()
        userrow=db.execute("SELECT id,email,role FROM users WHERE id=?",(job["requested_by"],)).fetchone(); user=dict(userrow); project_id=job["project_id"]; kind=job["kind"]; target=job["target"]; authorized=bool(job["authorized"]); public_authorized=bool(job["public_authorized"])
    finally: db.close()
    last_update=[0.0]
    def progress(value,message):
        now=time.monotonic()
        if value>=100 or now-last_update[0]>=.35:
            conn=connect()
            try: conn.execute("UPDATE scan_jobs SET progress=?,message=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'",(max(0,min(99,int(value))),str(message)[:240],job_id)); conn.commit()
            finally: conn.close()
            last_update[0]=now
    try:
        if event.is_set(): raise RuntimeError("Assessment cancelled")
        if kind=="network": result=assessments.network_assessment(target,authorized,public_authorized,progress,event.is_set)
        elif kind=="android_device":
            conn=connect()
            try:
                submitted=conn.execute("SELECT payload FROM scan_job_inputs WHERE job_id=?",(job_id,)).fetchone()
            finally: conn.close()
            if not submitted: raise RuntimeError("Android audit payload was not found")
            progress(25,"Reviewing consented Android device evidence")
            result=android_device.build_assessment(json.loads(authlib.decrypt_secret(submitted["payload"],SECRET)))
            android_device.protect_inventory(result,SECRET)
            progress(90,"Saving Android device audit results")
        elif kind=="android_adb":
            progress(10,"Connecting to the explicitly paired Android phone")
            result=android_adb.collect(target)
            android_device.protect_inventory(result,SECRET)
            progress(90,"Saving wireless Android device audit results")
        else:
            progress(10,"Collecting local system evidence"); result=assessments.local_assessment(); progress(90,"Saving assessment evidence")
        if event.is_set(): raise RuntimeError("Assessment cancelled")
        conn=connect()
        try:
            job=conn.execute("SELECT * FROM scan_jobs WHERE id=?",(job_id,)).fetchone()
            if not job or job["cancel_requested"] or event.is_set(): raise RuntimeError("Assessment cancelled")
            project_id=job["project_id"]
            asset_id=None
            if kind=="local":
                name=result.get("facts",{}).get("hostname","Local system"); row=conn.execute("SELECT id FROM assets WHERE project_id=? AND address='127.0.0.1' ORDER BY id LIMIT 1",(project_id,)).fetchone()
                if row: asset_id=row[0]; conn.execute("UPDATE assets SET name=?,hostname=?,asset_type='endpoint',criticality='high' WHERE id=?",(name,name,asset_id))
                else: asset_id=conn.execute("INSERT INTO assets(project_id,name,hostname,address,asset_type,criticality) VALUES(?,?,?,'127.0.0.1','endpoint','high') RETURNING id",(project_id,name,name)).fetchone()[0]
            assessment_kind="android_device" if kind=="android_adb" else kind
            assessment_id=persist_assessment(conn,user,project_id,asset_id,assessment_kind,result)
            if kind=="network":
                for host in result.get("hosts",[]):
                    row=conn.execute("SELECT id FROM assets WHERE project_id=? AND address=? ORDER BY id LIMIT 1",(project_id,host["address"])).fetchone()
                    if row: conn.execute("UPDATE assets SET hostname=? WHERE id=?",(host["hostname"],row[0]))
                    else: conn.execute("INSERT INTO assets(project_id,name,hostname,address,asset_type) VALUES(?,?,?,?,?)",(project_id,host["hostname"] or host["address"],host["hostname"],host["address"],"network"))
            job_result={"assessment_id":assessment_id,"summary":result.get("summary",{}),"scope":result.get("scope"),"scope_details":result.get("scope_details",{}),"network_summary":result.get("network_summary",{}),"severity_counts":result.get("severity_counts",{}),"hosts":result.get("hosts",[]),"services":result.get("services",[]),"findings":len(result.get("findings",[])),"warnings":result.get("warnings",result.get("scope_details",{}).get("warnings",[]))}
            if kind in ("android_device","android_adb"):
                device=result.get("facts",{}).get("device",{})
                job_result["device_summary"]={"manufacturer":device.get("manufacturer",""),"model":device.get("model",""),"android_version":device.get("android_version",""),"visible_app_count":result.get("facts",{}).get("visible_app_count",0),"checks_completed":result.get("scope_details",{}).get("checks_completed",0),"checks_unavailable":result.get("scope_details",{}).get("checks_unavailable",0)}
                conn.execute("DELETE FROM scan_job_inputs WHERE job_id=?",(job_id,))
            conn.execute("UPDATE scan_jobs SET status='completed',progress=100,message='Assessment completed',result=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(json.dumps(job_result),job_id)); conn.commit()
            LOG.info("Scan job completed id=%s kind=%s findings=%s",job_id,kind,len(result.get("findings",[])))
        finally: conn.close()
    except Exception as exc:
        cancelled=event.is_set() or str(exc)=="Assessment cancelled"
        conn=connect()
        try:
            status="cancelled" if cancelled else "failed"; conn.execute("UPDATE scan_jobs SET status=?,message=?,error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(status,"Assessment cancelled" if cancelled else "Assessment failed", "" if cancelled else str(exc)[:1000],job_id)); conn.execute("INSERT INTO audit_log(user_id,project_id,action,entity,details) VALUES(?,?,?,?,?)",(user["id"],project_id,"scan."+status,"scan_job",json.dumps({"job_id":job_id,"error":"" if cancelled else str(exc)[:1000]}))); conn.commit()
            LOG.warning("Scan job ended id=%s status=%s error_type=%s",job_id,status,type(exc).__name__)
        finally: conn.close()
    finally:
        with SCAN_LOCK: SCAN_EVENTS.pop(job_id,None)
def required(data,key,maxlen):
    s=data.get(key)
    if not isinstance(s,str) or not s.strip() or len(s.strip())>maxlen: raise ValueError(f"{key} is required (maximum {maxlen} characters)")
    return s.strip()
def valid_choice(value, choices):
    if value not in choices: raise ValueError("Invalid value")
    return value
def valid_bool(value, field):
    if value is True or value is False: return int(value)
    if type(value) is int and value in (0,1): return value
    raise ValueError(f"{field} must be a boolean")
def repair_admin(db,email,password):
    email=email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):
        raise ValueError("Enter a valid email address")
    if not authlib.valid_password(password):
        raise ValueError("Password must be 6–256 characters")
    user=db.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()
    if user:
        uid=user[0]
        db.execute("UPDATE users SET password_hash=?, role='admin' WHERE id=?",(pw_hash(password),uid))
    else:
        cur=db.execute("INSERT INTO users(email,password_hash,role) VALUES(?,?,'admin')",(email,pw_hash(password)))
        uid=cur.lastrowid
    org=db.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
    if not org:
        oid=db.execute("INSERT INTO organizations(name) VALUES(?)",(os.environ.get("AUDIT_ORGANIZATION","My Organization"),)).lastrowid
        db.execute("INSERT INTO projects(organization_id,name,description) VALUES(?, 'Security Baseline', 'Initial assessment project')",(oid,))
    else:
        oid=org[0]
    membership=db.execute("SELECT user_id, organization_id, role FROM memberships WHERE user_id=? AND organization_id=?",(uid,oid)).fetchone()
    if membership:
        db.execute("UPDATE memberships SET role='admin' WHERE user_id=? AND organization_id=?",(uid,oid))
    else:
        db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,'admin')",(uid,oid))
    grc.seed(db); db.commit()
    return uid

def create_admin(db,email,password,full_name="",username=""):
    if db.execute("SELECT count(*) FROM users").fetchone()[0]: return False
    email=email.strip().lower(); username=username.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,63}",email): raise ValueError("Enter a valid email address")
    if not authlib.valid_password(password): raise ValueError("Password must be at least 6 characters")
    if username and not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,39}",username): raise ValueError("Invalid username")
    cur=db.execute("INSERT INTO users(email,password_hash,role,full_name,username,is_email_verified) VALUES(?,?,'admin',?,?,1)",(email,pw_hash(password),full_name[:120],username)); uid=cur.lastrowid
    orgname=os.environ.get("AUDIT_ORGANIZATION","My Organization"); oid=db.execute("INSERT INTO organizations(name) VALUES(?)",(orgname,)).lastrowid; db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,'admin')",(uid,oid)); db.execute("INSERT INTO projects(organization_id,name,description) VALUES(?, 'Security Baseline', 'Initial assessment project')",(oid,)); db.execute("INSERT INTO security_events(user_id,event,success,details) VALUES(?, 'initial_admin_created', 1, ?)",(uid,json.dumps({"method":"first-admin setup"}))); grc.seed(db); db.commit(); return True
def main():
    level=os.environ.get("LOG_LEVEL","INFO").strip().upper()
    logging.basicConfig(level=getattr(logging,level,logging.INFO),format="%(asctime)s %(levelname)s %(name)s %(message)s",stream=sys.stdout)
    parser=argparse.ArgumentParser(); parser.add_argument("--init",action="store_true"); parser.add_argument("--create-admin",action="store_true"); parser.add_argument("--check",action="store_true"); parser.add_argument("--repair-admin",metavar="EMAIL",help="Create or repair a local admin account"); args=parser.parse_args(); db=connect(); grc.seed(db); db.commit()
    if args.init: print("Database initialized.")
    if args.create_admin:
        full_name=os.environ.get("AUDIT_ADMIN_NAME") or input("Full name: ").strip(); username=os.environ.get("AUDIT_ADMIN_USERNAME") or input("Username: ").strip(); email=os.environ.get("AUDIT_ADMIN_EMAIL") or input("Admin email: ").strip(); password=os.environ.get("AUDIT_ADMIN_PASSWORD") or getpass.getpass("Admin password (6+ characters): "); confirm=getpass.getpass("Confirm password: ") if not os.environ.get("AUDIT_ADMIN_PASSWORD") else password
        if password!=confirm: raise SystemExit("Passwords do not match.")
        print("Administrator created." if create_admin(db,email,password,full_name,username) else "An account already exists; no administrator was changed.")
    if args.repair_admin:
        password=getpass.getpass("New admin password (6+ characters): ")
        repair_admin(db,args.repair_admin,password)
        print(f"Admin account repaired: {args.repair_admin.strip().lower()}")
    if args.check:
        assert risk.score("high")["band"]=="high"; print("Database and risk checks passed.")
    if not (args.init or args.create_admin or args.check or args.repair_admin):
        host=os.environ.get("AUDIT_HOST","127.0.0.1"); port=int(os.environ.get("AUDIT_PORT","8080"))
        if host not in ("127.0.0.1","localhost","::1") and not SECRET_CONFIGURED: raise SystemExit("Set AUDIT_SECRET before binding beyond loopback.")
        cors_origin=os.environ.get("AUDIT_CORS_ORIGIN","")
        if cors_origin and not cors_origin.startswith("https://"): raise SystemExit("AUDIT_CORS_ORIGIN must use HTTPS when cross-origin cookies are enabled.")
        try:
            server = ThreadingHTTPServer((host, port), Handler)
        except OSError as e:
            if getattr(e, "winerror", None) == 10048 or "Address already in use" in str(e):
                raise SystemExit(
                    f"Port {port} is already in use. "
                    f"Stop the existing Sentinel Audit server and run .\\run.bat again."
                )
            raise SystemExit(f"Could not start Sentinel Audit on {host}:{port}: {e}")

        stale=db.execute("UPDATE scan_jobs SET status='failed',message='Server restarted before this scan completed',error='server_restart',updated_at=CURRENT_TIMESTAMP WHERE status IN ('queued','running')").rowcount
        if stale: LOG.warning("Marked %s interrupted scan(s) as failed; retry them from Assessment History",stale)
        db.commit()

        LOG.info("Sentinel Audit listening at http://%s:%s",host,port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            LOG.info("Sentinel Audit stopped")
        finally:
            server.server_close()
    db.close()
if __name__=="__main__": main()
