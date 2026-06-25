FROM python:3.11-slim

WORKDIR /app
COPY . /app
RUN useradd -r -u 10001 gateway && mkdir -p /data && chown -R gateway:gateway /app /data
USER gateway
EXPOSE 8080
CMD ["python", "-m", "defensive_ai_gateway", "--config", "config/prod.example.yaml"]

