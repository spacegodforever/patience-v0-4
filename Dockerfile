FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATIENCE_HOME=/data \
    PATIENCE_STATE_PATH=/data/patience_state.json PATIENCE_AUDIT_PATH=/data/patience_audit.jsonl \
    PATIENCE_APPROVERS=/data/approvers.yaml PATIENCE_AGENTS=/data/agents.yaml PATIENCE_DOTENV=/data/.env
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -u 10001 -m patience && mkdir -p /data && chown patience /data
USER patience
VOLUME ["/data"]
EXPOSE 8765 8501
# Loopback by default. Inside docker-compose the bind is widened to the container network only and
# the host port is published on 127.0.0.1 (see docker-compose.yml and docs/SECURITY.md).
ENV PATIENCE_BIND=127.0.0.1
CMD ["sh", "-c", "exec python -m uvicorn api:app --host \"$PATIENCE_BIND\" --port 8765 --workers 1"]
