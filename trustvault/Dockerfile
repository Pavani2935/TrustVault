FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TV_ENV=production

WORKDIR /app
RUN useradd --create-home --uid 10001 trustvault

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY trustvault ./trustvault
COPY gunicorn.conf.py ./
COPY scripts/start.sh ./start.sh
RUN chmod 0555 start.sh && chown -R root:root /app && chmod -R a-w /app/trustvault

# Runs as an unprivileged user; the application code is read-only to it.
USER trustvault
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/healthz')" || exit 1
CMD ["./start.sh"]
