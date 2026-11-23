FROM python:3.13-slim
RUN useradd --system --uid 10001 --no-create-home eufy && mkdir /data && chown eufy /data
WORKDIR /app
COPY scripts/ /app/
ENV PYTHONUNBUFFERED=1 EUFY_DB_PATH=/data/eufy_history.sqlite3
USER eufy
CMD ["python3", "server.py"]
