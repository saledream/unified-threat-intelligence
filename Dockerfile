FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system app && \
    useradd --system --gid app --home-dir /app app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app app/ ./app/
COPY --chown=app:app data/ ./data/

USER app

EXPOSE 3000

CMD ["python", "-m", "app.main"]
