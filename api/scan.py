import json
import time
import socket
import logging
import traceback
import ipaddress

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis import Redis
from rq import Queue
from rq.job import Job
import nmap

from config import (
    DEFAULT_OPTIONS,
    MAX_REQUESTS_PER_MINUTE,
    ALLOWED_ORIGINS,
    API_KEY,
    REDIS_URL,
    ip_allowed,
)

# -----------------------------
# Logging Setup
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scanner")

# -----------------------------
# Redis Setup
# -----------------------------
redis_conn = Redis.from_url(REDIS_URL, decode_responses=True)
queue = Queue("scans", connection=redis_conn)

# -----------------------------
# FastAPI App
# -----------------------------
app = FastAPI(title="Advanced Port Scanner API")

origins = (
    [o.strip() for o in ALLOWED_ORIGINS.split(",")]
    if ALLOWED_ORIGINS != "*"
    else ["*"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Rate Limiter (In-Memory)
# -----------------------------
_rate_limit_store = {}


def check_rate_limit(client_ip: str):
    now = time.time()
    window = 60
    requests = _rate_limit_store.setdefault(client_ip, [])

    while requests and requests[0] <= now - window:
        requests.pop(0)

    if len(requests) >= MAX_REQUESTS_PER_MINUTE:
        return False

    requests.append(now)
    return True


# -----------------------------
# Models
# -----------------------------
class ScanRequest(BaseModel):
    target: str
    options: str = DEFAULT_OPTIONS


# -----------------------------
# Helpers
# -----------------------------
def resolve_target(target: str):
    try:
        ipaddress.ip_address(target)
        return target
    except Exception:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None


def check_api_key(request: Request):
    if not API_KEY:
        return True

    key = request.headers.get("x-api-key")
    if not key:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth.split(None, 1)[1].strip()

    return key == API_KEY


# -----------------------------
# Background Scan
# -----------------------------
def run_scan(target: str, options: str):
    nm = nmap.PortScanner()
    start_time = time.time()

    try:
        nm.scan(target, arguments=options)
    except Exception as e:
        redis_conn.incr("metrics:failed_scans")
        return {"success": False, "error": str(e)}

    results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, data in nm[host][proto].items():
                results.append({
                    "host": host,
                    "hostname": nm[host].hostname(),
                    "protocol": proto,
                    "port": int(port),
                    "state": data.get("state"),
                    "service": data.get("name"),
                    "product": data.get("product"),
                    "version": data.get("version"),
                    "extrainfo": data.get("extrainfo"),
                    "cpe": data.get("cpe"),
                })

    duration = round(time.time() - start_time, 2)

    result = {
        "success": True,
        "meta": {
            "target": target,
            "options": options,
            "scan_time_seconds": duration,
            "timestamp": int(time.time()),
            "total_ports": len(results),
        },
        "ports": sorted(results, key=lambda x: x["port"]),
    }

    # Cache for 5 minutes
    redis_conn.setex(
        f"scan:{target}:{options}",
        300,
        json.dumps(result)
    )

    redis_conn.incr("metrics:total_scans")

    logger.info(json.dumps({
        "event": "scan_completed",
        "target": target,
        "duration": duration,
        "ports_found": len(results)
    }))

    return result


# -----------------------------
# Routes
# -----------------------------
@app.post("/scan")
def enqueue_scan(req: ScanRequest, request: Request):

    if not check_api_key(request):
        raise HTTPException(status_code=401, detail="Invalid API key")

    client_ip = request.client.host if request.client else "unknown"

    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    resolved = resolve_target(req.target)
    if not resolved:
        raise HTTPException(status_code=400, detail="Invalid target")

    if not ip_allowed(resolved):
        raise HTTPException(status_code=403, detail="Target not allowed")

    cache_key = f"scan:{resolved}:{req.options}"
    cached = redis_conn.get(cache_key)

    if cached:
        return {
            "cached": True,
            "result": json.loads(cached)
        }

    job = queue.enqueue(
        run_scan,
        resolved,
        req.options,
        result_ttl=3600,
        timeout=3600
    )

    logger.info(json.dumps({
        "event": "scan_requested",
        "target": resolved,
        "client_ip": client_ip
    }))

    return {"job_id": job.id}


@app.get("/scan/{job_id}")
def get_scan_status(job_id: str):

    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    response = {
        "job_id": job.id,
        "status": job.get_status(),
    }

    if job.is_finished:
        response["result"] = job.result

    if job.is_failed:
        response["error"] = job.exc_info

    return response


@app.get("/metrics")
def metrics():
    return {
        "total_scans": redis_conn.get("metrics:total_scans") or 0,
        "failed_scans": redis_conn.get("metrics:failed_scans") or 0,
    }


@app.get("/health")
def health():
    return {"status": "ok"}