import os
from redis import Redis
from rq import Worker, Queue

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

listen = ["scans"]
redis_conn = Redis.from_url(REDIS_URL)

if __name__ == "__main__":
    queues = [Queue(name, connection=redis_conn) for name in listen]
    worker = Worker(queues, connection=redis_conn)
    worker.work()