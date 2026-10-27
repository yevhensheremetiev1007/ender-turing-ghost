import argparse
import errno
import sys
from pathlib import Path

from pydantic import ValidationError

from ghost_deploy.config import DeployConfig, load_config
from ghost_deploy.hetzner import (
    Hetzner,
    HetznerError,
    Transport,
    deploy_host,
    destroy_host,
    extra_ports,
    verify_host,
)
from ghost_deploy.render import BundleError, render_bundle, write_bundle

_TUNNELS = ["none", "cloudflare", "tailscale", "wireguard", "custom"]


def main(argv: list[str] | None = None, transport: Transport | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghost-deploy",
        description="Deploy Ghost on Hetzner with SSH reachable only through a tunnel.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    render = sub.add_parser("render", help="write cloud-init and the compose stack")
    _add_bundle_args(render)
    deploy = sub.add_parser("deploy", help="create the firewall and the server")
    _add_bundle_args(deploy)
    destroy = sub.add_parser("destroy", help="delete the server and its firewall")
    destroy.add_argument("--env-file", type=Path, default=Path(".env"))
    verify = sub.add_parser("verify", help="check that SSH is closed and the blog ports are open")
    verify.add_argument("--env-file", type=Path, default=Path(".env"))
    verify.add_argument("--output", type=Path, default=Path("build"))
    args = parser.parse_args(argv)
    if args.command == "render":
        return _render(args.env_file, args.output, args.tunnel, args.tunnel_script)
    if args.command == "deploy":
        return _deploy(args.env_file, args.output, args.tunnel, args.tunnel_script, transport)
    if args.command == "destroy":
        return _destroy(args.env_file, transport)
    if args.command == "verify":
        return _verify(args.env_file, args.output, transport)
    parser.error(f"unknown command {args.command}")
    return 2


def _add_bundle_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--output", type=Path, default=Path("build"))
    parser.add_argument("--tunnel", choices=_TUNNELS, help="override TUNNEL from the env file")
    parser.add_argument(
        "--tunnel-script",
        type=Path,
        help="shell script installed on the host to expose 127.0.0.1:22",
    )


def _render(env_file: Path, output: Path, tunnel: str | None, tunnel_script: Path | None) -> int:
    try:
        config, script = _inputs(env_file, tunnel, tunnel_script)
        bundle = render_bundle(config, tunnel_script=script)
    except (ValidationError, OSError, BundleError, HetznerError) as exc:
        return _fail(exc, env_file)
    write_bundle(bundle, output)
    for name in bundle.files:
        print(output / name)
    print("database passwords are in ghost.env and cloud-init.yaml")
    print(bundle.files["connect.txt"], end="")
    return 0


def _deploy(
    env_file: Path,
    output: Path,
    tunnel: str | None,
    tunnel_script: Path | None,
    transport: Transport | None,
) -> int:
    try:
        config, script = _inputs(env_file, tunnel, tunnel_script)
        host = deploy_host(config, output, script, Hetzner(config.hetzner_api_token, transport))
    except (ValidationError, OSError, BundleError, HetznerError) as exc:
        return _fail(exc, env_file)
    print(f"server {host.name}")
    print("created" if host.created else "already exists")
    print(f"ipv4 {host.ipv4}")
    print(f"https://{config.domain}")
    connect = output / "connect.txt"
    if connect.is_file():
        print(connect.read_text(encoding="utf-8"), end="")
    return 0


def _destroy(env_file: Path, transport: Transport | None) -> int:
    try:
        config, _script = _inputs(env_file, None, None)
        result = destroy_host(config, Hetzner(config.hetzner_api_token, transport))
    except (ValidationError, OSError, BundleError, HetznerError) as exc:
        return _fail(exc, env_file)
    print(f"server {result.name}")
    print("deleted server" if result.deleted_server else "server already gone")
    print("deleted firewall" if result.deleted_firewall else "firewall already gone")
    return 0


def _verify(env_file: Path, output: Path, transport: Transport | None) -> int:
    try:
        config, _script = _inputs(env_file, None, None)
        ports_file = output / "tunnel-ports.txt"
        extra = extra_ports(ports_file.read_text(encoding="utf-8")) if ports_file.is_file() else []
        host = verify_host(config, Hetzner(config.hetzner_api_token, transport), extra=extra)
    except (ValidationError, OSError, BundleError, HetznerError) as exc:
        return _fail(exc, env_file)
    print(f"server {host.name}")
    print(f"ipv4 {host.ipv4}")
    print("firewall has no SSH rule")
    print("port 22 is closed")
    print("ports 80 and 443 are open")
    return 0


def _inputs(
    env_file: Path, tunnel: str | None, tunnel_script: Path | None
) -> tuple[DeployConfig, str | None]:
    if not env_file.is_file():
        raise FileNotFoundError(errno.ENOENT, "No such file", str(env_file))
    script = None
    if tunnel_script is not None:
        if not tunnel_script.is_file():
            raise FileNotFoundError(errno.ENOENT, "No such file", str(tunnel_script))
        script = tunnel_script.read_text(encoding="utf-8")
    config = load_config(env_file)
    if tunnel is not None:
        config = DeployConfig.model_validate(config.model_copy(update={"tunnel": tunnel}).model_dump())
    return config, script


def _fail(exc: Exception, env_file: Path) -> int:
    if isinstance(exc, FileNotFoundError):
        missing = exc.filename or env_file
        if str(missing) == str(env_file):
            print(f"missing {missing}. Copy .env.example to .env and fill it in.", file=sys.stderr)
        else:
            print(f"missing {missing}", file=sys.stderr)
        return 2
    print(exc, file=sys.stderr)
    return 2
