FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Third-party OSINT tools: one root-owned virtualenv each under /opt/tools, so
# the app user can execute but never modify them and their pins can't collide.
# Installed before the app so code changes don't rebuild this layer.
COPY scripts/install-tools.sh scripts/install-tools.sh
RUN TOOLS_DIR=/opt/tools sh scripts/install-tools.sh

COPY requirements.txt ./
RUN pip install --upgrade pip setuptools wheel && pip install -r requirements.txt

RUN useradd --system --create-home --uid 10001 unmask
COPY --chown=unmask:unmask . .
USER unmask

ENV UNMASK_ENV=production \
    UNMASK_QUEUE=rq \
    UNMASK_TOOLS_BIN=/opt/tools/bin \
    PORT=8000

EXPOSE 8000
CMD ["sh", "scripts/start.sh"]
