FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl unzip && \
    arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) xray_asset="Xray-linux-64.zip" ;; \
      arm64) xray_asset="Xray-linux-arm64-v8a.zip" ;; \
      *) echo "Unsupported architecture for Xray: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/latest/download/${xray_asset}" -o /tmp/xray.zip && \
    unzip -j /tmp/xray.zip xray -d /usr/local/bin && \
    chmod +x /usr/local/bin/xray && \
    rm -f /tmp/xray.zip && \
    apt-get purge -y --auto-remove curl unzip && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY common ./common

CMD ["sh", "-c", "if [ -z \"$DATABASE_URL\" ] && [ -n \"$SHREDDER_ADMIN_DATABASE_URL\" ]; then export DATABASE_URL=\"$SHREDDER_ADMIN_DATABASE_URL\"; fi; cd common && alembic upgrade head && cd /app && python3 -m app.main"]
