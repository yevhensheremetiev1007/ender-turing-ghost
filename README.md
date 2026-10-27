# ghost-deploy

`ghost-deploy render` writes a first-boot bundle for Ghost on Ubuntu 24.04. Cloud-init installs Ghost, MySQL, and Caddy. SSH accepts one public key and listens on `127.0.0.1` only.

Pass `--tunnel-script` to install the command that makes `127.0.0.1:22` reachable. The script runs as root after the host firewall is enabled.

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
ghost-deploy render --tunnel-script ./tunnel.sh --output build
```

`build/cloud-init.yaml` is the file to paste as Hetzner Cloud user data on an Ubuntu 24.04 server. The same directory contains the compose file, the Caddyfile, and `ghost.env` for review. Those files contain the database passwords, and the directory is gitignored.

Point the domain at the server, then open `https://<domain>/ghost` and create the owner account.

## What the host exposes

Caddy publishes `80/tcp`, `443/tcp`, and `443/udp`. Ghost and MySQL have no host ports. `sshd` listens on `127.0.0.1:22` for `ADMIN_USER` only, with password login disabled.

UFW denies other connections to services that run on the host. Ports published by Docker are separate from UFW, so `docker-compose.yml` is the list of public ports.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
