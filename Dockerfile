FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt requirements-tools.txt ./

# Application dependencies.
RUN pip install --upgrade pip setuptools wheel && pip install -r requirements.txt

# Third-party OSINT tools live in their own virtualenv, owned by root, so the
# app user can execute but never modify them, and their dependencies can't
# collide with the app's. They are only ever invoked as subprocesses.
RUN python -m venv /opt/tools \
    && /opt/tools/bin/pip install --upgrade pip setuptools wheel \
    && /opt/tools/bin/pip install -r requirements-tools.txt

RUN useradd --system --create-home --uid 10001 unmask
COPY --chown=unmask:unmask . .
USER unmask

ENV UNMASK_ENV=production \
    UNMASK_TOOLS_BIN=/opt/tools/bin \
    PORT=8000

EXPOSE 8000
CMD ["sh", "scripts/start.sh"]
