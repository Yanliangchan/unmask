"""Runtime configuration, loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRET = "dev-insecure-change-me"  # noqa: S105 — rejected at startup in production


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = Field(default="development", alias="UNMASK_ENV")
    app_name: str = "unmask"

    database_url: str = Field(
        default="postgresql+asyncpg://unmask:unmask@localhost:5432/unmask",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # Signs the session cookie. Not used for data encryption.
    secret_key: str = Field(default=_DEV_SECRET, alias="SECRET_KEY")

    # Data-at-rest keys. These must come from a secret store that is separate
    # from the database (see README > Key management). Comma-separated Fernet
    # keys: the first encrypts, all of them decrypt (enables rotation).
    data_keys: str = Field(default="", alias="UNMASK_DATA_KEYS")
    # HMAC key for the blind index used to look up encrypted values.
    index_key: str = Field(default="", alias="UNMASK_INDEX_KEY")

    public_base_url: str = Field(default="http://localhost:8000", alias="PUBLIC_BASE_URL")
    allow_indexing: bool = Field(default=True, alias="UNMASK_ALLOW_INDEXING")

    admin_email: str | None = Field(default=None, alias="UNMASK_ADMIN_EMAIL")
    admin_password: str | None = Field(default=None, alias="UNMASK_ADMIN_PASSWORD")

    session_max_age_seconds: int = 60 * 60 * 12
    login_max_attempts: int = 5
    login_window_seconds: int = 15 * 60

    tools_bin_dir: str = Field(default="", alias="UNMASK_TOOLS_BIN")
    tool_timeout_seconds: int = Field(default=300, alias="UNMASK_TOOL_TIMEOUT")
    # "inline" runs scans inside the web process (dev, tests); "rq" hands them
    # to worker services through Redis.
    queue_backend: str = Field(default="inline", alias="UNMASK_QUEUE")
    # Wall-clock cap for one scan run on a worker.
    scan_job_timeout_seconds: int = Field(default=2 * 60 * 60, alias="UNMASK_SCAN_JOB_TIMEOUT")

    # Per-tool settings. API keys are written to a 0600 config file inside the
    # tool's throwaway working directory, never passed on the command line.
    maigret_top_sites: int = Field(default=500, alias="UNMASK_MAIGRET_TOP_SITES")
    # h8mail keys as comma-separated name=value pairs, e.g. "hibp=...,snusbase_token=..."
    h8mail_keys: str = Field(default="", alias="UNMASK_H8MAIL_KEYS")
    harvester_sources: str = Field(
        default="crtsh,hackertarget,rapiddns,otx,certspotter,urlscan", alias="UNMASK_HARVESTER_SOURCES"
    )
    spiderfoot_use_case: str = Field(default="passive", alias="UNMASK_SPIDERFOOT_USE_CASE")
    crtsh_url: str = Field(default="https://crt.sh/", alias="UNMASK_CRTSH_URL")

    # Automatic pivots. Depth = how many pivot runs may chain off each other;
    # budget = most pivots one evaluation may start. Anything over is logged
    # as skipped, never silently dropped.
    pivot_max_depth: int = Field(default=2, alias="UNMASK_PIVOT_MAX_DEPTH")
    pivot_budget: int = Field(default=20, alias="UNMASK_PIVOT_BUDGET")
    pivot_email_providers: str = Field(
        default="gmail.com,outlook.com,yahoo.com,proton.me", alias="UNMASK_PIVOT_EMAIL_PROVIDERS"
    )

    # Scheduler: watch mode, retention purges and periodic health checks.
    # Runs in the RQ worker (or in the web process with UNMASK_QUEUE=inline).
    scheduler_enabled: bool = Field(default=True, alias="UNMASK_SCHEDULER")
    scheduler_interval_seconds: int = Field(default=300, alias="UNMASK_SCHEDULER_INTERVAL")
    # At most this many watch scans start per tick; the rest wait for later
    # ticks, so due cases never fire as one burst.
    watch_max_per_tick: int = Field(default=3, alias="UNMASK_WATCH_MAX_PER_TICK")
    healthcheck_interval_hours: int = Field(default=24, alias="UNMASK_HEALTHCHECK_HOURS")
    alert_webhook_url: str = Field(default="", alias="UNMASK_ALERT_WEBHOOK_URL")

    # Correlation. The model must already be on disk (the Docker image bakes it
    # in); set UNMASK_EMBEDDING_MODEL="" to turn pass 2 off.
    embedding_model: str = Field(default="sentence-transformers/all-MiniLM-L6-v2", alias="UNMASK_EMBEDDING_MODEL")
    embedding_cache_dir: str = Field(default="", alias="UNMASK_EMBEDDING_CACHE")
    embedding_threshold: float = Field(default=0.8, alias="UNMASK_EMBEDDING_THRESHOLD")

    @field_validator("database_url")
    @classmethod
    def _async_driver(cls, v: str) -> str:
        # Railway hands out postgres:// / postgresql:// URLs; we need asyncpg.
        if v.startswith("postgres://"):
            v = "postgresql://" + v[len("postgres://") :]
        if v.startswith("postgresql://"):
            v = "postgresql+asyncpg://" + v[len("postgresql://") :]
        return v

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def validate_for_startup(self) -> None:
        problems = []
        if not self.data_keys:
            problems.append("UNMASK_DATA_KEYS is not set")
        if not self.index_key:
            problems.append("UNMASK_INDEX_KEY is not set")
        if self.is_production:
            if self.secret_key == _DEV_SECRET or len(self.secret_key) < 32:
                problems.append("SECRET_KEY must be a random value of at least 32 characters")
            if self.secret_key in self.data_keys or self.secret_key == self.index_key:
                problems.append("SECRET_KEY must not reuse an encryption key")
            if self.data_keys and self.data_keys in self.database_url:
                problems.append("encryption key material must not live in DATABASE_URL")
        if problems:
            raise RuntimeError("Invalid configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
