# shredder-admin

Small internal admin for Shredder config templates.

## What it does

- Stores custom config templates in the shared Postgres database.
- Lets you edit templates from a browser.
- Exposes `GET /api/config-templates/next` for round-robin template delivery.
- The response contains the raw Jinja-compatible JSON template in `content`.

## Run locally

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up -d --build
```

Open:

```text
http://127.0.0.1:8015/
```

Database migrations are applied automatically on container startup:

```bash
alembic upgrade head
```

The JSON templates are stored in Postgres in `admin_config_templates.content`.

## Protect the browser UI

Before exposing the admin through a public domain, set:

```env
SHREDDER_ADMIN_UI_USERNAME="admin"
SHREDDER_ADMIN_UI_PASSWORD="long-random-password"
```

The API token is separate and is used by `shredder-custom-config`:

```env
SHREDDER_ADMIN_TOKEN="same-token-as-in-shredder-custom-config"
```

## Seed from current custom config

```bash
mkdir -p seed
cp ../shredder-custom-config/template.json seed/template.json
```

Set:

```env
SHREDDER_ADMIN_SEED_TEMPLATE_PATH=/app/seed/template.json
```

The seed is imported only if the table is empty.

## Connect custom-config

Add this to `shredder-custom-config/.env` when both services are in
`remnawave-network`:

```env
SHREDDER_ADMIN_CONFIG_NEXT_URL=http://shredder-admin:8015/api/config-templates/next
SHREDDER_ADMIN_TOKEN=your-token-if-set
SHREDDER_ADMIN_REQUEST_TIMEOUT=5
```

Every subscription request asks this endpoint for the next active template.
If the admin is unavailable, `shredder-custom-config` falls back to local
`template.json`.

## API

```bash
curl http://127.0.0.1:8015/api/config-templates/next
```

With token:

```bash
curl -H "X-Admin-Token: $SHREDDER_ADMIN_TOKEN" \
  http://127.0.0.1:8015/api/config-templates/next
```
