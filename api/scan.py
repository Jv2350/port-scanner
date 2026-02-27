from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis import Redis
from rq import Queue
from rq.job import Job
import nmap
import traceback
import socket
import time
import ipaddress
import os

# -----------------------------
# Redis Connection
# -----------------------------
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_conn = Redis.from_url(redis_url)

q = Queue("scans", connection=redis_conn)

app = FastAPI(title="Port Scanner Service")

# -----------------------------
# CORS
# -----------------------------
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
# Simple in-memory rate limiter
# -----------------------------
_rl_store = {}


class ScanRequest(BaseModel):
    target: str
    options: str = DEFAULT_OPTIONS


# -----------------------------
# Background Scan Function
# -----------------------------
def _run_scan(target: str, options: str):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=options)
    except Exception as exc:
        return {"error": str(exc), "trace": traceback.format_exc()}

    output = {}

    for host in nm.all_hosts():
        host_info = {
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "protocols": {},
        }

        for proto in nm[host].all_protocols():
            ports = []
            for port in nm[host][proto].keys():
                p = nm[host][proto][port]
                ports.append(
                    {
                        "port": int(port),
                        "state": p.get("state"),
                        "service": p.get("name"),
                    }
                )
            host_info["protocols"][proto] = ports

        output[host] = host_info

    return {"result": output}


# -----------------------------
# Helper Functions
# -----------------------------
def _resolve_to_ip(target: str):
    try:
        ipaddress.ip_address(target)
        return target
    except Exception:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None


def _check_rate_limit(client_ip: str):
    now = time.time()
    window = 60
    data = _rl_store.setdefault(client_ip, [])

    while data and data[0] <= now - window:
        data.pop(0)

    if len(data) >= MAX_REQUESTS_PER_MINUTE:
        return False

    data.append(now)
    return True


def _check_api_key(request: Request):
    if not API_KEY:
        return True

    key = request.headers.get("x-api-key")
    if not key:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth.split(None, 1)[1].strip()

    return key == API_KEY


# -----------------------------
# Routes
# -----------------------------
@app.post("/scan")
def enqueue_scan(req: ScanRequest, request: Request):
    if not req.target:
        raise HTTPException(status_code=400, detail="target is required")

    if not _check_api_key(request):
        raise HTTPException(status_code=401, detail="invalid api key")

    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    resolved = _resolve_to_ip(req.target)
    if not resolved:
        raise HTTPException(status_code=400, detail="could not resolve target")

    job = q.enqueue(
        _run_scan,
        req.target,
        req.options,
        result_ttl=3600,
        timeout=3600,
    )

    return {"job_id": job.id}


@app.get("/scan/{job_id}")
def get_status(job_id: str):
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    response = {
        "id": job.id,
        "status": job.get_status(),
    }

    if job.is_finished:
        response["result"] = job.result

    if job.is_failed:
        response["error"] = job.exc_info

    return response


@app.get("/health")
def health():
    return {"status": "ok"}