from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from redis import Redis
from rq import Queue
from rq.job import Job
import nmap
import traceback

# Connection and queue
redis_conn = Redis()  # default: localhost:6379
q = Queue("scans", connection=redis_conn)

app = FastAPI(title="Port Scanner Service")


class ScanRequest(BaseModel):
    target: str
    # default to a non-privileged TCP scan; users who run as root can pass -sS
    options: str = "-sT -sV"


def _run_scan(target: str, options: str):
    """Background worker function that performs the nmap scan.
    Returns a JSON-serializable dict with results or error info.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=options)
    except Exception as exc:
        return {"error": str(exc), "trace": traceback.format_exc()}

    out = {}
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
                ports.append({
                    "port": int(port),
                    "state": p.get("state"),
                    "service": p.get("name"),
                })
            host_info["protocols"][proto] = ports
        out[host] = host_info

    return {"result": out}


@app.post("/scan")
def enqueue_scan(req: ScanRequest):
    """Enqueue a scan job. Returns a job id that can be polled.
    Request body: {"target": "1.2.3.4", "options": "-sT -sV"}
    """
    if not req.target:
        raise HTTPException(status_code=400, detail="target is required")

    job = q.enqueue(_run_scan, req.target, req.options, result_ttl=60 * 60, timeout=60 * 60)
    return {"job_id": job.get_id()}


@app.get("/scan/{job_id}")
def get_status(job_id: str):
    """Get job status and result (when finished)."""
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    resp = {"id": job.get_id(), "status": job.get_status()}
    if job.is_finished:
        resp["result"] = job.result
    if job.is_failed:
        resp["exc_info"] = job.exc_info
    return resp


# Simple health endpoint
@app.get("/health")
def health():
    return {"status": "ok"}
