# Build from verify/:  docker build -f hosted/Dockerfile -t verify-hosted .
FROM python:3.12-slim
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" && useradd -r -u 10001 app
WORKDIR /app
COPY src/ /app/src/
COPY hosted/ /app/hosted/
ENV PYTHONPATH=/app/src:/app PYTHONUNBUFFERED=1 VERIFY_BIND=0.0.0.0
USER app
EXPOSE 8080
# Requires VERIFY_EXPORT_KEY and VERIFY_DATABASE_URL (postgres://...) at runtime.
CMD ["python", "-m", "hosted.server", "serve", "8080"]
