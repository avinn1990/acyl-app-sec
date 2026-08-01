# acyl — personal local AppSec platform
# Default command: web dashboard on :8787
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="acyl"
LABEL org.opencontainers.image.description="Personal local AppSec platform (Foundry-lite + CodeGuard + Antares + dashboard)"
LABEL org.opencontainers.image.source="https://github.com/avinn1990/acyl-app-sec"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/data \
    ACYL_DATA_DIR=/data/.cache/acyl \
    ACYL_RULES_DIR=/app/rules \
    ACYL_MODEL_MOCK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY rules ./rules
COPY goals ./goals
COPY examples ./examples
COPY fixtures ./fixtures
COPY specs ./specs
COPY vendor ./vendor
COPY scripts ./scripts
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
 && pip install --upgrade pip \
 && pip install .

RUN useradd --create-home --home-dir /data --shell /bin/bash acyl \
 && mkdir -p /data/.cache/acyl /targets \
 && chown -R acyl:acyl /data /targets /app

USER acyl
VOLUME ["/data", "/targets"]
EXPOSE 8787 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dashboard"]
