FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install . \
    && useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/logs /app/approvals \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

VOLUME ["/app/logs", "/app/approvals"]

ENTRYPOINT ["agentic-misp-mcp"]
CMD ["--transport", "stdio"]
