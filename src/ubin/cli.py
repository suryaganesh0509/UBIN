from __future__ import annotations

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import stat
import sys

import ubin


def _passphrase_from_args(args) -> str:
    env_name = getattr(args, "passphrase_env", None)
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"environment variable {env_name!r} is not set")
        return value
    return getpass("UBIN passphrase: ")


def _write_key(path: Path, key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key.hex().encode("ascii") + b"\n")
    finally:
        os.close(fd)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _read_key(path: Path) -> bytes:
    try:
        raw = path.read_text(encoding="ascii").strip()
        return bytes.fromhex(raw)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"invalid UBIN key file: {path}") from exc


def _print_receipt(receipt) -> None:
    if hasattr(receipt, "__dataclass_fields__"):
        data = {}
        for name in receipt.__dataclass_fields__:
            value = getattr(receipt, name)
            data[name] = str(value) if isinstance(value, Path) else value
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(receipt)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ubin",
        description="UBIN v1.0.3 — universal binary access and secure transport/carriers",
    )
    parser.add_argument("--version", action="version", version=f"UBIN {ubin.__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="inspect a file without loading it fully")
    info.add_argument("source")

    digest = sub.add_parser("hash", help="stream a file hash")
    digest.add_argument("source")
    digest.add_argument("--algorithm", default="sha256")

    secure = sub.add_parser("secure", help="create a local authenticated .ubs container")
    secure.add_argument("source")
    secure.add_argument("output")
    secure.add_argument("--key-out", required=True, help="new 0600 file for the local container key")
    secure.add_argument("--overwrite", action="store_true")

    restore = sub.add_parser("restore", help="restore a local .ubs container")
    restore.add_argument("source")
    restore.add_argument("output")
    restore.add_argument("--key-file", required=True)
    restore.add_argument("--overwrite", action="store_true")

    image = sub.add_parser("image-pack", help="create an authenticated lossless PNG carrier")
    image.add_argument("source")
    image.add_argument("output")
    image.add_argument("--passphrase-env", help="read passphrase from this environment variable instead of prompting")
    image.add_argument("--width", type=int, default=1024)
    image.add_argument("--overwrite", action="store_true")

    image_restore = sub.add_parser("image-restore", help="restore a UBIN PNG carrier")
    image_restore.add_argument("source")
    image_restore.add_argument("output", nargs="?")
    image_restore.add_argument("--passphrase-env", help="read passphrase from this environment variable instead of prompting")
    image_restore.add_argument("--overwrite", action="store_true")

    demo = sub.add_parser("demo", help="launch the local UBIN browser demonstration")
    demo.add_argument("--port", type=int, default=5055)
    demo.add_argument("--no-browser", action="store_true")

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "info":
            with ubin.open(args.source) as obj:
                print(json.dumps({
                    "name": obj.name,
                    "path": str(obj.path),
                    "size": obj.size,
                    "type": obj.type,
                }, indent=2, sort_keys=True))
            return 0

        if args.command == "hash":
            with ubin.open(args.source) as obj:
                print(obj.hash(args.algorithm))
            return 0

        if args.command == "secure":
            key_path = Path(args.key_out).expanduser()
            if key_path.exists():
                raise SystemExit(f"key file already exists: {key_path}")
            receipt = ubin.secure(args.source).save(args.output, overwrite=args.overwrite)
            try:
                _write_key(key_path, receipt.key)
            except Exception:
                Path(receipt.output).unlink(missing_ok=True)
                raise
            print(f"Local key written with owner-only permissions: {key_path}")
            safe = {
                "output": str(receipt.output),
                "original_size": receipt.original_size,
                "frame_count": receipt.frame_count,
                "sha256": receipt.sha256,
                "session_id": receipt.session_id,
            }
            print(json.dumps(safe, indent=2, sort_keys=True))
            return 0

        if args.command == "restore":
            receipt = ubin.decrypt(
                args.source,
                args.output,
                key=_read_key(Path(args.key_file).expanduser()),
                overwrite=args.overwrite,
            )
            _print_receipt(receipt)
            return 0

        if args.command == "image-pack":
            receipt = ubin.to_image(
                args.source,
                args.output,
                passphrase=_passphrase_from_args(args),
                width=args.width,
                overwrite=args.overwrite,
            )
            _print_receipt(receipt)
            return 0

        if args.command == "image-restore":
            receipt = ubin.from_image(
                args.source,
                args.output,
                passphrase=_passphrase_from_args(args),
                overwrite=args.overwrite,
            )
            _print_receipt(receipt)
            return 0

        if args.command == "demo":
            from .demo import run_demo
            run_demo(port=args.port, open_browser=not args.no_browser)
            return 0

        raise SystemExit("unknown command")
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except ubin.UbinError as exc:
        print(f"UBIN error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
