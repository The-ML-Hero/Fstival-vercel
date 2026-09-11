# Vercel + Render PostgreSQL deployment

Deploy this repository as two Vercel projects.

## Backend

- Import the repository into Vercel with the root directory set to `.`.
- Vercel serves `api/index.py`, which exposes the FastAPI application.
- Set these environment variables:

```text
APP_ENV=production
DEBUG=false
DATABASE_URL=postgresql+asyncpg://USER:PASSWORD@HOST:PORT/DATABASE?ssl=require
ALLOWED_ORIGINS=["https://YOUR-FRONTEND.vercel.app"]
AI_PROVIDER=fallback
REQUIRE_TARGET_AUTHORIZATION_FOR_EXECUTION=true
```

Use Render's external PostgreSQL connection string, replacing `postgresql://` with `postgresql+asyncpg://`.

## Frontend

- Create a second Vercel project from the same repository with root directory `frontend`.
- Set `NEXT_PUBLIC_API_URL` to `https://YOUR-BACKEND.vercel.app/api/v1`.

## Operational limit

Vercel functions have ephemeral local storage. Do not depend on generated Bruno collections surviving between requests. The FastAPI async runner is appropriate for this deployment; run long Bruno jobs in a separate worker service.
