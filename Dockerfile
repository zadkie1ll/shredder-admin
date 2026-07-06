FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY common ./common

CMD ["sh", "-c", "if [ -z \"$DATABASE_URL\" ] && [ -n \"$SHREDDER_ADMIN_DATABASE_URL\" ]; then export DATABASE_URL=\"$SHREDDER_ADMIN_DATABASE_URL\"; fi; cd common && alembic upgrade head && cd /app && python3 -m app.main"]
