# ghost-deploy

`ghost-deploy render` writes a first-boot bundle for Ghost on Ubuntu 24.04. Cloud-init installs Ghost, MySQL, and Caddy. SSH accepts one public key and listens on `127.0.0.1` only.

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

`build/cloud-init.yaml` is the file to paste as Hetzner Cloud user data on an Ubuntu 24.04 server. The same directory contains the compose file, the Caddyfile, `ghost.env`, and `connect.txt`. Tunnel credentials and database passwords are inside `cloud-init.yaml`. The directory is gitignored.

`connect.txt` is the command that reaches the host. For WireGuard it also points at `wireguard-client.conf`, which stays on your machine. The server only receives the client public key.

## Tunnels

| `TUNNEL` | What you set | How you connect |
|---|---|---|
| `cloudflare` | `CLOUDFLARE_TUNNEL_TOKEN` | `cloudflared access ssh` to the TCP hostname, default `ssh.<domain>` |
| `tailscale` | `TAILSCALE_AUTH_KEY` | `tailscale ssh <admin>@<hostname>` |
| `wireguard` | optional `WIREGUARD_ENDPOINT` | import `wireguard-client.conf`, then `ssh <admin>@10.66.0.1` |
| custom | `--tunnel-script` | whatever that script exposes, aimed at `127.0.0.1:22` |

Cloudflare and Tailscale open no extra inbound ports. WireGuard needs UDP `51820` (or the port in `WIREGUARD_ENDPOINT`) allowed in the Hetzner firewall. `build/tunnel-ports.txt` lists those ports. The host rule is already in the tunnel script, and SSH on WireGuard is limited to the `wg0` interface.

Point the domain at the server, then open `https://<domain>/ghost` and create the owner account.

## What the host exposes

Caddy publishes `80/tcp`, `443/tcp`, and `443/udp`. Ghost and MySQL have no host ports. `sshd` listens on `127.0.0.1:22` for `ADMIN_USER` only, with password login disabled.

UFW denies other connections to services that run on the host. Ports published by Docker are separate from UFW, so `docker-compose.yml` is the list of public ports.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
