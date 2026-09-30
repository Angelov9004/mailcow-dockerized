FROM python:3.12-slim-bookworm

LABEL maintainer = "mailcow Python port"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      tini \
      tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 8080 mailcow \
    && useradd -u 8080 -g mailcow -d /app -s /usr/sbin/nologin mailcow

# Dependencies are installed into the image; the application code itself is bind mounted from ./data/api
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

WORKDIR /app
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/docker-entrypoint.sh"]
CMD ["uvicorn", "mailcow.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "2", "--no-server-header"]
