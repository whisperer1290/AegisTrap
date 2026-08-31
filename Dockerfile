FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    AEGISTRAP_LLM_PROVIDER=offline \
    AEGISTRAP_HOST=0.0.0.0 \
    AEGISTRAP_DASHBOARD_ENABLED=true

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY aegistrap ./aegistrap

RUN useradd --create-home --uid 10001 aegistrap \
    && mkdir -p /app/data /app/reports \
    && chown -R aegistrap:aegistrap /app

USER aegistrap

EXPOSE 8000

# Bind 0.0.0.0 inside the container; compose publishes 127.0.0.1 on the host.
CMD ["python", "-m", "aegistrap", "--host", "0.0.0.0", "--port", "8000"]
