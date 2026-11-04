# Deploy with Dokploy

Use `compose.dokploy.yaml` as a standalone Docker Compose deployment. It builds the dashboard, API, and MCP from this repository and includes PostgreSQL and persistent intelligence storage. Select **Docker Compose**, not Docker Stack: this configuration builds images on the server.

## 1. Create the service

In your Dokploy project, create a **Compose** service. Choose GitHub or Git as the source, repository `https://github.com/saledream/unified-threat-intelligence`, branch `main`, and Compose Path `./compose.dokploy.yaml`. Keep the repository root as the build context. Do not combine this file with `compose.yaml`.

The Dokploy host needs enough available disk and memory to build the Next.js frontend and Python images. Actual requirements depend on imported datasets and workload. Review the build logs if a process is killed for lack of memory.

## 2. Set environment variables

Copy `.env.dokploy.example` into the Compose service's **Environment** editor. Set:

```dotenv
PUBLIC_HOSTNAME=intel.your-domain.com
POSTGRES_DB=threat_intel
POSTGRES_USER=threat_intel
POSTGRES_PASSWORD=YOUR_RANDOM_DATABASE_PASSWORD
JWT_SECRET_KEY=YOUR_RANDOM_SECRET_AT_LEAST_32_CHARACTERS
```

Use your real hostname without a scheme or path. Generate separate random secrets, for example with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Add your provider keys to the corresponding fields. Leave unused integrations blank. This template selects personal usage modes; use them only for your own non-business use under each provider's terms.

Dokploy writes the editor values to `.env`; the API, MCP, and optional feed worker load it through `env_file`. The frontend receives only its internal API URL, not provider keys. Do not upload your credentials to GitHub.

For an existing database, retain its actual database name, username, password, JWT secret, and storage encryption key. Editing initialization credentials does not rename an existing PostgreSQL user or database. Preserve the Compose project and named volumes across redeployments.

## 3. Configure the dashboard domain

Point your hostname's DNS record at the Dokploy server. In the service's **Domains** tab, add the hostname with:

| Setting | Value |
|---|---|
| Service | `threat-intel-frontend` |
| Container port | `3000` |
| Path | `/` |
| HTTPS | Enabled, with an appropriate certificate |

Deploy or redeploy after saving domain changes. Dokploy manages the proxy routing. Only the frontend joins `dokploy-network`; it forwards `/api/*` to the API over the stack's private network. Do not add a public domain for PostgreSQL or MCP in this configuration.

## 4. Deploy and create an administrator

Click **Deploy** and inspect the service logs. PostgreSQL becomes healthy first, then the API creates its tables, and dependent services start.

Open a terminal in the running **threat-intel-api** container through Dokploy and run:

```sh
python -m app.api.bootstrap_admin
```

Enter your username and a password of at least 12 characters. Open `https://intel.your-domain.com` and sign in. Check provider configuration and try a permitted public IOC. This guide prepares the deployment; a successful live server deployment must be verified on your Dokploy instance.

## 5. Connect an agent without MCP authentication

MCP has no authentication or token expiry in this deployment. It is published only on the Dokploy host's loopback interface at port 3002. Dashboard login and human submission approval remain enabled.

For an agent on another computer, use an SSH tunnel:

```sh
ssh -N -L 3002:127.0.0.1:3002 your-user@your-dokploy-server
```

Keep the tunnel open. Configure the agent on that computer with:

```yaml
mcp_servers:
  threat_intelligence:
    url: http://127.0.0.1:3002/mcp
```

The tunnel uses your existing SSH access; the MCP itself requires no login. An agent running directly on the Dokploy host can use the URL without a tunnel. A containerized agent has its own localhost and needs a separately configured private network connection. If port 3002 is occupied, change `MCP_HOST_PORT` in Dokploy and the tunnel's remote port accordingly.

## Data, updates, and checks

- `postgres_data` stores accounts, provider settings, and audits. `intel_data` stores imported intelligence, encrypted pending records, and request quota state. Back up both named volumes and preserve the configuration secrets.
- Redeploy after changing provider keys. Reuse the same volumes and project; do not remove volumes during an update.
- To synchronize feeds once, run `python -m app.services.feeds --once` in the API container. Import references through the dashboard or run `python -m app.services.knowledge attack` in that container.
- The optional recurring feed worker uses the `feeds` profile. Enable that profile in your Compose command only when desired; preserve Dokploy's generated project/path arguments when customizing its command.
- Verify dashboard login, a provider lookup, MCP tool discovery through the tunnel, and data persistence after a normal redeploy. Account-dependent provider errors should remain visible.
- If the proxy returns 502, check frontend build/startup logs and the domain's service/port. If API requests return 400, confirm `PUBLIC_HOSTNAME` matches the dashboard hostname. If storage is unwritable, inspect volume ownership; the application containers run as a non-root user.

Official references: [Dokploy Compose](https://docs.dokploy.com/docs/core/docker-compose), [Compose example](https://docs.dokploy.com/docs/core/docker-compose/example), and [domain configuration](https://docs.dokploy.com/docs/core/docker-compose/domains).
