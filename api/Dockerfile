FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# copy project
COPY . /app

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "api.scan:app", "--host", "0.0.0.0", "--port", "8000"]
