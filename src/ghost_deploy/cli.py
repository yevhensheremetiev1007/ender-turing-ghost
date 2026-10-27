import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from ghost_deploy.config import load_config
from ghost_deploy.render import BundleError, render_bundle, write_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghost-deploy",
        description="Render a Ghost bootstrap bundle with SSH bound to localhost.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    render = sub.add_parser("render", help="write cloud-init and the compose stack")
    render.add_argument("--env-file", type=Path, default=Path(".env"))
    render.add_argument("--output", type=Path, default=Path("build"))
    render.add_argument(
        "--tunnel-script",
        type=Path,
        help="shell script installed on the host to expose 127.0.0.1:22",
    )
    args = parser.parse_args(argv)
    if args.command == "render":
        return _render(args.env_file, args.output, args.tunnel_script)
    parser.error(f"unknown command {args.command}")
    return 2


def _render(env_file: Path, output: Path, tunnel_script: Path | None) -> int:
    if not env_file.is_file():
        print(f"missing {env_file}. Copy .env.example to .env and fill it in.", file=sys.stderr)
        return 2
    script = None
    if tunnel_script is not None:
        if not tunnel_script.is_file():
            print(f"missing {tunnel_script}", file=sys.stderr)
            return 2
        script = tunnel_script.read_text(encoding="utf-8")
    try:
        config = load_config(env_file)
        bundle = render_bundle(config, tunnel_script=script)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print(exc, file=sys.stderr)
        return 2
    except BundleError as exc:
        print(exc, file=sys.stderr)
        return 2
    write_bundle(bundle, output)
    for name in bundle.files:
        print(output / name)
    print("database passwords are in ghost.env and cloud-init.yaml")
    return 0
