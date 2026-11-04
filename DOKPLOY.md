# Deploy the search page with Dokploy

## Configure

1. Create a project and a **Compose** service. Choose **Docker Compose**, not Stack.
2. Select `https://github.com/saledream/unified-threat-intelligence`, branch `main`, Compose Path `./compose.dokploy.yaml`.
3. Copy `.env.dokploy.example` into **Environment**. Set `PUBLIC_HOSTNAME=intel.your-domain.com` without a scheme/path and enter your provider keys. This template selects personal usage modes, which require your own non-business use and permitted provider access.
4. Point the hostname's DNS at the server. In **Domains**, route that hostname to service **threat-intel-frontend**, container port **3000**, path `/`, and enable HTTPS.
5. Click **Deploy**. When the frontend and API are healthy, open your domain. There is no login, administrator bootstrap, or PostgreSQL setup.

The Compose file builds from the repository and loads provider configuration from Dokploy's generated `.env`. Only the frontend joins `dokploy-network`. It forwards `/api/*` to the API privately. MCP has no authentication and is bound to the server's loopback interface at port 3002.

The search website and API intentionally have no authentication. Anyone who can reach the website can search using your server's provider credentials and quotas. Keys are kept server-side and are not returned to the browser.

## Connect an agent

An agent running on the server can connect to `http://127.0.0.1:3002/mcp`. For an agent on another computer, keep an SSH tunnel open:

```sh
ssh -N -L 3002:127.0.0.1:3002 your-user@your-server
```

Configure that computer's agent with:

```yaml
mcp_servers:
  threat_intelligence:
    url: http://127.0.0.1:3002/mcp
```

No application token or expiry is involved. SSH uses your existing server access. A containerized agent has its own localhost and needs a private network connection configured separately.

## Operate

- Redeploy after changing provider keys or domains.
- Keep the same project and `intel_data` named volume to preserve imported data and request quota counters. Optional encrypted caches require preserving their storage key.
- Accounts, roles, authentication, administrative endpoints, and submissions are not exposed. Old PostgreSQL volumes are left untouched on upgrades; no deletion is performed automatically.
- Import feeds in an API container terminal with `python -m app.services.feeds --once`. Import reference data with `python -m app.services.knowledge attack`. The optional recurring feed worker uses the `feeds` profile.
- If a deployment returns 502, check the frontend build/startup logs, API health, and the domain's service and port. For a 400 response, verify `PUBLIC_HOSTNAME` matches your domain. If a build is killed, check server memory and disk capacity.
- Verify a search, provider error visibility, MCP tool discovery, and data persistence on your server. Compose validation does not establish that a live Dokploy deployment has succeeded.

Official references: [Compose](https://docs.dokploy.com/docs/core/docker-compose) and [Domains](https://docs.dokploy.com/docs/core/docker-compose/domains).
