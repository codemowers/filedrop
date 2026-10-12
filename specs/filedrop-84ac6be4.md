# File drop: private uploads and a public gallery

Build and deploy a small file-sharing application in the assigned sandbox
namespace. Use the platform's OIDC and S3 offerings where needed. Create a
private GitHub repository if none is selected. Keep a concise `progress.md`,
verify the finished flows, and report infrastructure blockers instead of
guessing credentials, permissions, or registry settings.

## Access modes

Make the instance access mode configurable without changing application code:

| Mode | Browse public files | Upload | Browse private files |
| --- | --- | --- | --- |
| `anonymous` | Anyone | Anyone | Owner or holder of that file's private link |
| `upload-authenticated` (default) | Anyone | Signed-in users | Owner or holder of that file's private link |
| `enforced-auth` | Signed-in users | Signed-in users | Owner or holder of that file's private link, after sign-in |

The mode applies to the whole instance. Show the active mode and the required
sign-in step clearly in the UI. Changing mode must immediately affect API and
file access, not merely hide buttons. In `anonymous` mode, give each uploader a
high-entropy, unguessable management link for viewing and deleting their own
uploads. Show it once with a clear warning that losing it means losing control
of the upload. Do not treat a browser-supplied name as proof of ownership.

Use the platform's OIDCClient for sign-in. Discover its writable schema and
admission rules through Driftmower. Use Authorization Code with PKCE for a
browser client; never send a client secret to the browser. Validate access
token signature, issuer, audience, and expiry on the API. Identify signed-in
owners by verified issuer and subject. Enforce the access matrix on every
listing, metadata, download, preview, edit, and delete route.

## Upload and sharing

- Allow drag and drop and file selection, multiple files, upload progress, and
  clear retryable errors. Show a file's name, size, type, owner-facing actions,
  visibility, expiry, and share URL after upload.
- For each file, let its owner choose **public** or **private** and an optional
  expiry. These are separate settings: either visibility can expire. Default
  new uploads to private with no expiry. Owners can change visibility, set or
  remove expiry, and delete their files.
- Public files appear in the newest-first index at `/` while they are active.
  Show only safe metadata and a preview when available. Include pagination or
  bounded loading; a single large gallery must not load every object at once.
- A private file is absent from public listings and search. Its unguessable
  read-only link can be opened by someone without OIDC in the first two modes;
  `enforced-auth` requires sign-in before opening it. Owners can revoke and
  regenerate a private link without re-uploading the file. Possessing a read
  link never grants edit or delete access.
- Expired files disappear from listings and all read/share routes immediately
  according to server time. A background cleanup removes their objects and
  metadata eventually; failure to clean up must not make them readable again.
  Show the exact expiry time and time zone before saving it. An owner may extend
  an expiry only before the file has expired.
- Set documented per-file and total upload limits. Check actual content type
  and size on the server; do not trust the extension or browser MIME label.
  Reject executable HTML/SVG preview content or serve it as a download with
  safe headers. Use generated object keys rather than client-supplied paths.
- Protect anonymous uploads with configurable rate, size, and storage limits.
  Failed uploads must not leave indefinitely retained orphan objects.

## Preview and download

Use native browser previews for safe, supported types: `<img>` for common
raster images, `<audio controls>` for audio, and `<video controls>` for video.
Offer a plain-text preview for small UTF-8 text files and a browser PDF preview
only if it can be isolated safely. Keep every file downloadable, including
types without previews. Never inject uploaded HTML into the application page,
execute scripts from uploaded content, or expose S3 credentials to browsers.

Preview and download endpoints must check current visibility, link validity,
instance access mode, and expiry on every request. Support HTTP range requests
for playable media. Send suitable content type, `nosniff`, disposition, and
cache headers so revoked or expired content does not remain available through
long-lived public caches. A thumbnail or preview is governed by the same
access rules as its original.

## Storage and deployment

Use the namespace-local S3 Bucket and S3User offered by the platform. Discover
schemas, admission policies, namespace readiness, and exact operation access
through Driftmower before creating manifests. Read endpoint and credentials
from operator-generated Secrets; keep them server-side. Store file objects in
private S3 storage even when an application URL is public. Persist metadata,
ownership, hashed share/management tokens, expiry, and cleanup state in a
durable store offered in the namespace. Choose the simplest supported store
that can enforce atomic visibility and deletion updates.

Ask the controller MCP for namespace context and a Skaffold example/schema;
validate `skaffold.yaml` before running it. Build through Skaffold's cluster
Kaniko builder and push only to the verified namespace registry destination.
Use the existing kubeconfig and namespace identity. Let admission supply
managed image, security, TLS, and short-host settings. Read the admitted
Ingress to report the actual URL. Stop on uncertain access, storage, builder,
or credential configuration rather than inventing a workaround.

## Completion

Deliver committed code, validated Skaffold configuration, manifests, usage
documentation, and the deployed URL. Verify all three access modes, public
indexing, private link revocation, expiry enforcement, cross-user isolation,
and image/audio/video preview with representative files. Report the actual
checks performed and any unresolved limitations.