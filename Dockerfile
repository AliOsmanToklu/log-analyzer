# syntax=docker/dockerfile:1

# Build wheels for the app and its dependencies, so the final image needs no build tools
FROM python:3.14-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[api,postgres]"

FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOG_ANALYZER_DATABASE_URL=sqlite:////home/app/data/log_analyzer.db

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels "log-analyzer[api,postgres]" \
    && rm -rf /wheels \
    && useradd --create-home --uid 10001 app

USER app
WORKDIR /home/app
# Only used when no external database is configured
RUN mkdir data
VOLUME /home/app/data

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

# Applies pending migrations, then serves
CMD ["log-analyzer-api", "serve", "--host", "0.0.0.0", "--port", "8000"]
