FROM python:3.11-slim

WORKDIR /opt/stealthtap

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt
COPY . .

# Default entrypoint; each service in docker-compose.yml overrides this
# (api -> uvicorn, streaming-engine -> faust, log-shipper -> log_shipper).
ENTRYPOINT ["python", "-m", "src.offline_engine"]