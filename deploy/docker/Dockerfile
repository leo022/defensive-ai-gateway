FROM python:3.11-slim

WORKDIR /app
COPY . /app
RUN useradd -r -u 10001 gateway && mkdir -p /data && chown -R gateway:gateway /app /data
USER gateway
# Production: set DEFENSIVE_AI_API_TOKEN (shared bearer token for the HTTP API)
# and DEFENSIVE_AI_LLM_API_KEY via the orchestrator (k3s secret / systemd env).
# Front with mTLS / a reverse proxy; the app binds 0.0.0.0 only behind it.
EXPOSE 8080
CMD ["python", "-m", "defensive_ai_gateway", "--config", "config/prod.example.yaml"]

