@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0security_audit;%PYTHONPATH%"
if not defined AUDIT_HOST set "AUDIT_HOST=127.0.0.1"
if not defined AUDIT_PORT set "AUDIT_PORT=8080"
start "" "http://localhost:%AUDIT_PORT%/"
python -m security_audit
pause