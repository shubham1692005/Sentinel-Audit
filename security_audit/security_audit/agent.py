"""Organization-bound outbound scanner agent for private IPv4 assessments."""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from . import assessments


def request(server, token, path, payload=None, timeout=60):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(server.rstrip("/") + path, data=body, method="GET" if payload is None else "POST", headers={"Authorization": "Bearer " + token, "Accept": "application/json", **({"Content-Type": "application/json"} if body is not None else {})})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Sentinel returned a response that exceeds the agent size limit")
    return json.loads(raw.decode("utf-8"))


def run(server, token, poll_seconds=5):
    if not token:
        raise ValueError("Provide the enrolled agent token through SENTINEL_AGENT_TOKEN")
    if not server.startswith("https://") and not server.startswith("http://127.0.0.1") and not server.startswith("http://localhost"):
        raise ValueError("Use HTTPS for the Sentinel server URL")
    print("Sentinel scanner agent is online. Press Ctrl+C to stop.", flush=True)
    while True:
        try:
            payload = request(server, token, "/api/agent/next", timeout=30)
            job = payload.get("job")
            if not job:
                time.sleep(poll_seconds)
                continue
            print("Running authorized private scope " + job["target"], flush=True)
            try:
                scope = assessments.validate_scope(job["target"], bool(job["authorized"]), bool(job["public_authorized"]))
                if not scope.is_private or scope.is_loopback or scope.is_link_local:
                    raise ValueError("Agent accepts private, non-loopback IPv4 scope only")
                def progress(value, message):
                    state = request(server, token, "/api/agent/jobs/" + job["id"] + "/progress", {"progress": int(value), "message": str(message)[:240]}, timeout=30)
                    if state.get("cancelled"):
                        raise RuntimeError("Assessment cancelled by a Sentinel user")
                result = assessments.network_assessment(str(scope), True, False, progress_callback=progress)
                request(server, token, "/api/agent/jobs/" + job["id"] + "/result", {"result": result}, timeout=180)
                print("Assessment result submitted.", flush=True)
            except Exception as exc:
                message = str(exc)[:400]
                try:
                    request(server, token, "/api/agent/jobs/" + job["id"] + "/result", {"error": message}, timeout=30)
                except Exception as submit_error:
                    print("Unable to submit scan failure: " + str(submit_error)[:200], file=sys.stderr, flush=True)
                print("Private assessment failed: " + message, file=sys.stderr, flush=True)
        except urllib.error.HTTPError as exc:
            detail = exc.read(1000).decode("utf-8", "replace")
            raise RuntimeError(f"Sentinel agent API rejected the request ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            print("Sentinel connection unavailable: " + str(exc.reason), file=sys.stderr, flush=True)
            time.sleep(min(30, poll_seconds * 2))


def main():
    parser = argparse.ArgumentParser(description="Run an enrolled Sentinel private-network scanner agent")
    parser.add_argument("--server", default=os.environ.get("SENTINEL_SERVER_URL", ""), help="Sentinel HTTPS base URL")
    parser.add_argument("--poll-seconds", type=int, default=5)
    args = parser.parse_args()
    try:
        run(args.server, os.environ.get("SENTINEL_AGENT_TOKEN", ""), max(2, min(args.poll_seconds, 30)))
    except KeyboardInterrupt:
        print("Scanner agent stopped.", flush=True)
    except Exception as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
