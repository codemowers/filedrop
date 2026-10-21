# FileDrop Progress

## Status: Building

## What's done
- Node.js/Express backend: upload, gallery, download, share links, OIDC PKCE auth, anonymous management tokens, expiry, cleanup
- Vanilla JS frontend: gallery, upload with progress, file preview (images/audio/video/PDF/text), OIDC login, owner actions
- SQLite metadata store (PVC with sqlite storage class)
- S3 storage (Bucket + Policy + S3User via s3.onyxia.sh CRDs)
- OIDCClient (codemowers.cloud/v1) with PKCE, no client secret, ingressRef
- Ingress with short hostname `filedrop` (expanded by platform admission)
- Skaffold config validated (v4beta11, Kaniko cluster builder)

## Access modes implemented
- `anonymous` — anyone browses and uploads; management token shown once
- `upload-authenticated` (default) — anyone browses; signed-in users upload
- `enforced-auth` — sign-in required for everything

## Known items to verify after deploy
- S3 endpoint: `http://minio.minio:9000` — update ConfigMap `filedrop-config` if incorrect
- OIDCClient ingressRef requires `passmower.ingressDiscovery.enabled`; if not available, add explicit `uri`/`redirectUris` with expanded hostname
- Actual public URL: read admitted Ingress after deployment

## Files
- `src/index.js` — Express app + all routes
- `src/db.js` — SQLite setup
- `src/s3.js` — S3 client (AWS SDK v3)
- `src/auth.js` — OIDC discovery + JWT validation (jsonwebtoken + jwks-rsa)
- `public/index.html` + `public/app.js` — SPA frontend
- `k8s/` — Bucket, Policy, S3User, OIDCClient, PVC, ConfigMap, Deployment, Service, Ingress
- `skaffold.yaml` — Kaniko cluster build → zot registry

## Dependency bump (issue #1, 2026-10-21)
- All deps on latest: express 5, multer 2, better-sqlite3 13, express-rate-limit 8, jwks-rsa 4, latest AWS SDK v3; base image node:24-alpine
- `uuid` dropped in favour of `crypto.randomUUID()`; `npm audit` clean
- Express 5 fixes: SPA fallback route `/{*splat}`, PUT tolerates missing body
- Verified locally against fake S3/OIDC in all three access modes; not yet redeployed (worker lacks namespace access)

