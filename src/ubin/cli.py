from __future__ import annotations

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import stat
import subprocess
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
        description="UBIN v2.0.0 — recommended stable universal runtime",
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

    capabilities = sub.add_parser("list", help="list bundled and installed UBIN capabilities")
    capabilities.add_argument("--json", action="store_true", dest="as_json")
    capabilities.add_argument("--verbose", action="store_true")
    cap_info = sub.add_parser("capability-info", help="describe one UBIN capability")
    cap_info.add_argument("capability")
    verify = sub.add_parser("verify-capability", help="verify capability discovery or provider manifest")
    verify.add_argument("capability")
    verify.add_argument("--load-provider", action="store_true")
    permissions = sub.add_parser("permissions", help="show declared maximum permissions for a capability")
    permissions.add_argument("capability")
    doctor = sub.add_parser("doctor", help="diagnose the UBIN runtime")
    doctor.add_argument("--deep", action="store_true")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    init = sub.add_parser("init", help="create ubin.toml for a reproducible UBIN project")
    init.add_argument("--path", default="ubin.toml")
    init.add_argument("--overwrite", action="store_true")
    lock = sub.add_parser("lock", help="create ubin.lock from ubin.toml")
    lock.add_argument("--config", default="ubin.toml")
    lock.add_argument("--output", default="ubin.lock")
    sync = sub.add_parser("sync", help="verify the current environment against ubin.lock")
    sync.add_argument("--lock", default="ubin.lock")
    sub.add_parser("protocol-vector", help="print UBIN v2 stable conformance vectors")

    add = sub.add_parser("add", help="add or verify a UBIN capability provider")
    add.add_argument("capability")
    add.add_argument("--package", help="explicit provider package/spec to install with pip")
    add.add_argument("--upgrade", action="store_true", help="allow pip to upgrade the provider")
    add.add_argument("--dry-run", action="store_true", help="print the pip action without changing the environment")

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

        if args.command == "list":
            rows = ubin.capabilities()
            if args.as_json:
                print(json.dumps([
                    {
                        "name": item.name,
                        "kind": item.kind,
                        "provider": item.provider,
                        "loaded": item.loaded,
                        "description": item.description,
                    }
                    for item in rows
                ], indent=2, sort_keys=True))
            else:
                print(f"{'CAPABILITY':<16} {'KIND':<10} {'LOADED':<8} PROVIDER")
                for item in rows:
                    print(
                        f"{item.name:<16} {item.kind:<10} "
                        f"{('yes' if item.loaded else 'no'):<8} {item.provider}"
                    )
                    if args.verbose:
                        print(f"  {item.description}")
            return 0

        if args.command == "capability-info":
            item = ubin.capability_info(args.capability)
            print(json.dumps({
                "name": item.name,
                "kind": item.kind,
                "provider": item.provider,
                "loaded": item.loaded,
                "description": item.description,
            }, indent=2, sort_keys=True))
            return 0
        if args.command == "verify-capability":
            result = ubin.verify_capability(args.capability, load_provider=args.load_provider)
            print(json.dumps({
                "name": result.name,
                "ok": result.ok,
                "kind": result.kind,
                "provider": result.provider,
                "message": result.message,
            }, indent=2, sort_keys=True))
            return 0 if result.ok else 2
        if args.command == "permissions":
            permissions = ubin.permissions.for_capability(args.capability)
            print(json.dumps({
                "capability": args.capability.strip().lower(),
                "granted": list(permissions.granted()),
            }, indent=2, sort_keys=True))
            return 0
        if args.command == "doctor":
            report = ubin.doctor(deep=args.deep)
            if args.as_json:
                print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
            else:
                print(f"UBIN {report.ubin_version} | Python {report.python_version}")
                for check in report.checks:
                    print(f"{'PASS' if check.ok else 'FAIL':<4} {check.name}: {check.detail}")
                print("HEALTHY" if report.healthy else "UNHEALTHY")
            return 0 if report.healthy else 2
        if args.command == "init":
            print(ubin.environment.init(args.path, overwrite=args.overwrite))
            return 0
        if args.command == "lock":
            print(ubin.environment.lock(args.config, args.output))
            return 0
        if args.command == "sync":
            result = ubin.environment.sync(args.lock)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["ok"] else 2
        if args.command == "protocol-vector":
            print(json.dumps(ubin.protocol.conformance_vector(), indent=2, sort_keys=True))
            return 0
        if args.command == "add":
            name = args.capability.strip().lower()
            existing = next(
                (item for item in ubin.capabilities() if item.name == name),
                None,
            )
            if existing is not None:
                if existing.kind == "builtin":
                    print(f"UBIN capability {name!r} is already bundled.")
                else:
                    print(
                        f"UBIN capability {name!r} is already installed "
                        f"from provider {existing.provider!r}."
                    )
                return 0

            if not args.package:
                print(
                    f"UBIN capability {name!r} has no installed provider. "
                    f"Install an explicitly trusted provider with: "
                    f"ubin add {name} --package PACKAGE",
                    file=sys.stderr,
                )
                return 2

            package = args.package.strip()
            if not package:
                print("provider package must not be empty", file=sys.stderr)
                return 2
            if package.startswith("-"):
                print("provider package must not begin with '-'", file=sys.stderr)
                return 2

            command = [sys.executable, "-m", "pip", "install"]
            if args.upgrade:
                command.append("--upgrade")
            command.append(package)

            if args.dry_run:
                print("DRY RUN:", " ".join(command))
                return 0

            print(f"Installing explicit UBIN provider for capability {name!r}: {package}")
            result = subprocess.run(command, check=False)
            if result.returncode != 0:
                return result.returncode

            installed = next(
                (item for item in ubin.capabilities() if item.name == name),
                None,
            )
            if installed is None:
                print(
                    f"Package {package!r} installed, but it did not register "
                    f"UBIN capability {name!r} in entry-point group 'ubin.capabilities'.",
                    file=sys.stderr,
                )
                return 2

            print(
                f"UBIN capability {name!r} is ready from provider "
                f"{installed.provider!r}."
            )
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
