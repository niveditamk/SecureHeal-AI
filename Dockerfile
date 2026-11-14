# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# --- Stage 2: Runtime ---
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /install /usr/local
COPY secureheal/ ./secureheal/
COPY target_services/ ./target_services/
COPY vulnerability_cases/ ./vulnerability_cases/

EXPOSE 8000

CMD ["uvicorn", "secureheal.main:app", "--host", "0.0.0.0", "--port", "8000"]
