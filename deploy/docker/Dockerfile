FROM python:3.11-slim

ARG APP_VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Defensive AI Gateway" \
      org.opencontainers.image.description="Offline-ready defensive AI gateway for banking SOC environments" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEFENSIVE_AI_HOST=0.0.0.0 \
    DEFENSIVE_AI_PORT=8080 \
    DEFENSIVE_AI_DB=/data/gateway.db

WORKDIR /app

RUN useradd --system --uid 10001 --create-home --home-dir /home/gateway gateway \
    && mkdir -p /data \
    && chown gateway:gateway /data

COPY --chown=gateway:gateway defensive_ai_gateway /app/defensive_ai_gateway
COPY --chown=gateway:gateway config/container.yaml /app/config/container.yaml
COPY --chown=gateway:gateway samples /app/samples
COPY --chown=gateway:gateway samples_syslog /app/samples_syslog

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=4 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=2).read()"]

ENTRYPOINT ["python", "-m", "defensive_ai_gateway"]
CMD ["--config", "config/container.yaml"]
