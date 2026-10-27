# ghost-deploy

`ghost-deploy deploy` creates a Hetzner Cloud server for Ghost. The firewall is attached in the create call and has no SSH rule. Cloud-init installs Ghost, MySQL, and Caddy. SSH accepts one public key and listens on `127.0.0.1` only.

Set `TUNNEL` to reach that port. Cloudflare and Tailscale make an outbound connection. WireGuard listens on UDP and then allows SSH only on `wg0`. A custom script can do the same job via `--tunnel-script`. The script runs as root after the host firewall is enabled.

## Configure

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
```

Fill in the domain, the ACME email, and one OpenSSH public key. Database passwords are optional: an empty value is generated into the bundle. Passwords are letters and digits, 16 to 128 characters.

## Render

```bash
ghost-deploy render --output build
ghost-deploy render --tunnel cloudflare --output build
ghost-deploy render --tunnel tailscale --output build
ghost-deploy render --tunnel wireguard --output build
ghost-deploy render --tunnel-script ./tunnel.sh --output build
```

`build/cloud-init.yaml` is the user data `deploy` sends to Hetzner. The same directory contains the compose file, the Caddyfile, `ghost.env`, and `connect.txt`. Tunnel credentials and database passwords are inside `cloud-init.yaml`. The API token stays in the environment. The directory is gitignored.

`connect.txt` is the command that reaches the host. For WireGuard it also points at `wireguard-client.conf`, which stays on your machine. The server only receives the client public key.

## Tunnels

| `TUNNEL` | What you set | How you connect |
|---|---|---|
| `cloudflare` | `CLOUDFLARE_TUNNEL_TOKEN` | `cloudflared access ssh` to the TCP hostname, default `ssh.<domain>` |
| `tailscale` | `TAILSCALE_AUTH_KEY` | `tailscale ssh <admin>@<hostname>` |
| `wireguard` | optional `WIREGUARD_ENDPOINT` | import `wireguard-client.conf`, then `ssh <admin>@10.66.0.1` |
| custom | `--tunnel-script` | whatever that script exposes, aimed at `127.0.0.1:22` |

Cloudflare and Tailscale open no extra inbound ports. WireGuard needs UDP `51820` (or the port in `WIREGUARD_ENDPOINT`). `deploy` adds that port from `tunnel-ports.txt`. SSH on WireGuard is limited to the `wg0` interface.

## Deploy

```bash
ghost-deploy deploy
ghost-deploy verify
ghost-deploy destroy
```

`deploy` creates the firewall, then an Ubuntu 24.04 server that already uses it. The default server is `cx23` in `fsn1`. A second run sees the existing server and does not create another one. The command prints the IPv4 address and the tunnel command from `connect.txt`.

Point an A record at that address, wait until cloud-init finishes, then run `verify`. It checks that the firewall has no SSH rule, that port 22 does not accept a connection from this machine, and that ports 80 and 443 do. Open `https://<domain>/ghost` and create the owner account.

`destroy` deletes that server and then its firewall.

## What the host exposes

Caddy publishes `80/tcp`, `443/tcp`, and `443/udp`. Ghost and MySQL have no host ports. `sshd` listens on `127.0.0.1:22` for `ADMIN_USER` only, with password login disabled.

UFW denies other connections to services that run on the host. Ports published by Docker are separate from UFW, so `docker-compose.yml` is the list of public ports.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
