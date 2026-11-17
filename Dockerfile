FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/security_audit AUDIT_HOST=0.0.0.0 AUDIT_PORT=8080 AUDIT_DB=/data/audit.db NMAP_PATH=/usr/bin/nmap
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt && rm /app/requirements.txt
COPY security_audit /app/security_audit
COPY web /app/web
RUN mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=3)"
CMD ["python", "-m", "security_audit"]
