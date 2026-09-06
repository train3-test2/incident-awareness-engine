FROM python:3.13-slim

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src"

COPY --from=ghcr.io/astral-sh/uv:0.12.10 /uv /uvx /bin/

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src

RUN groupadd --system app && useradd --system --gid app --create-home app

USER app
