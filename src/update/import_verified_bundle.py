#!/usr/bin/env python3
"""
Jeffrey Toolkit — offline import verified offline bundle importer v1.

This importer:
- accepts only a regular bundle file directly under /data/jeffrey-updates/incoming;
- invokes the bundle verifier verifier using a fixed executable path;
- never uses tar extract/extractall;
- re-streams and re-hashes every verified payload while staging;
- writes only inside a root-owned transaction directory;
- atomically renames the completed transaction into releases/<bundle_id>;
- creates no activation/current pointer;
- performs no network access;
- executes no bundle-supplied command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema

IMPORTER_VERSION = "offline-importer-v1"

ROOT = Path("/data/jeffrey-updates")
INCOMING = ROOT / "incoming"
STAGING = ROOT / "staging"
RELEASES = ROOT / "releases"
LOGS = ROOT / "logs"

VERIFIER = Path("/opt/jeffrey-update/bin/verify_offline_bundle.py")
RELEASE_SCHEMA = Path("/opt/jeffrey-update/schemas/offline-release-v1.schema.json")

MAX_COPY_CHUNK = 1024 * 1024
FREE_SPACE_MARGIN = 64 * 1024 * 1024


class ImportErrorSafe(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        path: str = "$",
        details: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.details = details


def emit(obj: dict[str, Any]) -> None:
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


def err_json(exc: ImportErrorSafe) -> dict[str, Any]:
    out: dict[str, Any] = {
        "valid": False,
        "error": exc.code,
        "message": exc.message,
        "path": exc.path,
        "importer_version": IMPORTER_VERSION,
    }
    if exc.details is not None:
        out["details"] = exc.details
    return out


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(MAX_COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def require_root_layout() -> None:
    for path in (ROOT, INCOMING, STAGING, RELEASES, LOGS):
        try:
            st = path.lstat()
        except FileNotFoundError as exc:
            raise ImportErrorSafe(
                "layout_missing",
                f"required offline import path is missing: {path}",
            ) from exc

        if path.is_symlink() or not path.is_dir():
            raise ImportErrorSafe(
                "unsafe_layout",
                f"required offline import path is not a real directory: {path}",
            )

        if st.st_uid != 0:
            raise ImportErrorSafe(
                "unsafe_layout_owner",
                f"required offline import path must be root-owned: {path}",
            )

        if st.st_mode & 0o022:
            raise ImportErrorSafe(
                "unsafe_layout_permissions",
                f"required offline import path must not be group/world writable: {path}",
            )


def canonical_incoming_bundle(path: Path) -> Path:
    if not path.is_absolute():
        raise ImportErrorSafe(
            "bundle_path_rejected",
            "bundle path must be absolute",
            "$.bundle",
        )

    try:
        parent_resolved = path.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ImportErrorSafe(
            "bundle_path_rejected",
            "bundle parent does not exist",
            "$.bundle",
        ) from exc

    if parent_resolved != INCOMING.resolve(strict=True):
        raise ImportErrorSafe(
            "bundle_outside_incoming",
            "bundle must be a direct child of the incoming directory",
            "$.bundle",
        )

    if path.name in {"", ".", ".."} or "/" in path.name or "\\" in path.name:
        raise ImportErrorSafe(
            "bundle_name_rejected",
            "bundle filename is invalid",
            "$.bundle",
        )

    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise ImportErrorSafe(
            "bundle_missing",
            f"bundle does not exist: {path}",
            "$.bundle",
        ) from exc

    if path.is_symlink():
        raise ImportErrorSafe(
            "bundle_symlink_rejected",
            "incoming bundle must not be a symlink",
            "$.bundle",
        )

    if not path.is_file():
        raise ImportErrorSafe(
            "bundle_not_regular",
            "incoming bundle must be a regular file",
            "$.bundle",
        )

    if st.st_uid != 0:
        raise ImportErrorSafe(
            "bundle_owner_rejected",
            "incoming bundle must be root-owned",
            "$.bundle",
        )

    if st.st_mode & 0o022:
        raise ImportErrorSafe(
            "bundle_permissions_rejected",
            "incoming bundle must not be group/world writable",
            "$.bundle",
        )

    return path


def run_verifier(bundle: Path) -> dict[str, Any]:
    if not VERIFIER.is_file():
        raise ImportErrorSafe(
            "verifier_missing",
            f"bundle verifier verifier is missing: {VERIFIER}",
        )

    proc = subprocess.run(
        [
            str(VERIFIER),
            "--bundle",
            str(bundle),
            "--signature-policy",
            "sha256",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=3600,
        check=False,
    )

    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ImportErrorSafe(
            "verifier_protocol_error",
            "bundle verifier verifier did not return valid JSON",
        ) from exc

    if proc.returncode != 0 or result.get("valid") is not True:
        raise ImportErrorSafe(
            "bundle_verification_failed",
            "bundle verifier bundle verification failed",
            "$.bundle",
            {"verifier_result": result},
        )

    if result.get("activation_performed") is not False:
        raise ImportErrorSafe(
            "verifier_protocol_error",
            "verifier unexpectedly reported activation",
        )

    if result.get("internet_access_performed") is not False:
        raise ImportErrorSafe(
            "verifier_protocol_error",
            "verifier unexpectedly reported network access",
        )

    return result


def load_release_schema() -> dict[str, Any]:
    try:
        schema = json.loads(RELEASE_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        return schema
    except Exception as exc:
        raise ImportErrorSafe(
            "release_schema_unavailable",
            f"release schema unavailable: {RELEASE_SCHEMA}",
        ) from exc


def safe_payload_relative(name: str) -> Path:
    p = PurePosixPath(name)

    if (
        not name.startswith("payload/")
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in p.parts)
        or str(p) != name
    ):
        raise ImportErrorSafe(
            "verified_path_invalid",
            "verifier returned an unsafe payload path",
            name,
        )

    rel = Path(*p.parts)
    if rel.is_absolute():
        raise ImportErrorSafe(
            "verified_path_invalid",
            "verified payload path unexpectedly absolute",
            name,
        )

    return rel


def open_destination(path: Path) -> Any:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags, 0o640)
    return os.fdopen(fd, "wb")


def write_json_atomic(path: Path, obj: Any, mode: int = 0o640) -> None:
    tmp = path.with_name(path.name + ".tmp")
    data = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise

    os.replace(tmp, path)


def read_archive_metadata(
    tf: tarfile.TarFile,
    member_name: str,
    max_bytes: int,
) -> bytes | None:
    try:
        member = tf.getmember(member_name)
    except KeyError:
        return None

    if not member.isfile():
        raise ImportErrorSafe(
            "archive_changed_after_verify",
            f"{member_name} is not a regular file",
            member_name,
        )

    if member.size > max_bytes:
        raise ImportErrorSafe(
            "archive_changed_after_verify",
            f"{member_name} exceeds metadata size limit",
            member_name,
        )

    f = tf.extractfile(member)
    if f is None:
        raise ImportErrorSafe(
            "archive_changed_after_verify",
            f"could not read {member_name}",
            member_name,
        )
    return f.read(max_bytes + 1)


def stage_payloads(
    bundle: Path,
    tx_dir: Path,
    verification: dict[str, Any],
) -> None:
    expected = {
        item["path"]: item
        for item in verification["payloads"]
    }

    with tarfile.open(bundle, mode="r:*") as tf:
        for name in sorted(expected):
            spec = expected[name]
            rel = safe_payload_relative(name)

            try:
                member = tf.getmember(name)
            except KeyError as exc:
                raise ImportErrorSafe(
                    "archive_changed_after_verify",
                    "verified payload disappeared before staging",
                    name,
                ) from exc

            if not member.isfile():
                raise ImportErrorSafe(
                    "archive_changed_after_verify",
                    "verified payload is no longer a regular file",
                    name,
                )

            if member.size != spec["size"]:
                raise ImportErrorSafe(
                    "archive_changed_after_verify",
                    "payload size changed after verification",
                    name,
                )

            src = tf.extractfile(member)
            if src is None:
                raise ImportErrorSafe(
                    "archive_changed_after_verify",
                    "could not stream verified payload",
                    name,
                )

            dst = tx_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True, mode=0o750)

            # Transaction directory is root-owned/private, but still reject
            # any unexpected symlink in the created parent chain.
            cur = tx_dir
            for part in rel.parts[:-1]:
                cur = cur / part
                if cur.is_symlink():
                    raise ImportErrorSafe(
                        "staging_symlink_rejected",
                        "unexpected symlink in staging path",
                        str(cur),
                    )

            h = hashlib.sha256()
            written = 0

            with open_destination(dst) as out:
                while True:
                    chunk = src.read(MAX_COPY_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > spec["size"]:
                        raise ImportErrorSafe(
                            "archive_changed_after_verify",
                            "payload exceeded verified size during staging",
                            name,
                        )
                    h.update(chunk)
                    out.write(chunk)

                out.flush()
                os.fsync(out.fileno())

            if written != spec["size"]:
                raise ImportErrorSafe(
                    "archive_changed_after_verify",
                    "staged payload size differs from verified size",
                    name,
                )

            digest = h.hexdigest()
            if digest != spec["sha256"]:
                raise ImportErrorSafe(
                    "archive_changed_after_verify",
                    "staged payload SHA256 differs from verified SHA256",
                    name,
                )

        manifest_raw = read_archive_metadata(tf, "manifest.json", 1024 * 1024)
        if manifest_raw is None:
            raise ImportErrorSafe(
                "archive_changed_after_verify",
                "manifest.json disappeared before staging",
            )

        manifest_path = tx_dir / "manifest.json"
        with open_destination(manifest_path) as f:
            f.write(manifest_raw)
            f.flush()
            os.fsync(f.fileno())

        sig_raw = read_archive_metadata(tf, "manifest.sig", 1024 * 1024)
        if sig_raw is not None:
            sig_path = tx_dir / "manifest.sig"
            with open_destination(sig_path) as f:
                f.write(sig_raw)
                f.flush()
                os.fsync(f.fileno())


def append_event(event: dict[str, Any]) -> None:
    LOGS.mkdir(mode=0o750, parents=True, exist_ok=True)
    log_path = LOGS / "import-events.jsonl"

    line = json.dumps(event, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(log_path, flags, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def import_bundle(bundle: Path) -> dict[str, Any]:
    require_root_layout()
    bundle = canonical_incoming_bundle(bundle)

    bundle_sha_before = sha256_path(bundle)
    verification = run_verifier(bundle)

    bundle_id = verification.get("bundle_id")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise ImportErrorSafe(
            "verifier_protocol_error",
            "verified result has no bundle_id",
        )

    release_dir = RELEASES / bundle_id
    if release_dir.exists() or release_dir.is_symlink():
        raise ImportErrorSafe(
            "release_exists",
            "release for this bundle_id already exists",
            str(release_dir),
        )

    total_payload_bytes = int(verification.get("total_payload_bytes", 0))
    free = shutil.disk_usage(STAGING).free
    needed = total_payload_bytes + FREE_SPACE_MARGIN
    if free < needed:
        raise ImportErrorSafe(
            "insufficient_space",
            "not enough free staging space",
            str(STAGING),
            {"free_bytes": free, "required_bytes": needed},
        )

    tx_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{bundle_id}.",
            dir=str(STAGING),
        )
    )
    os.chmod(tx_dir, 0o700)

    committed = False
    try:
        stage_payloads(bundle, tx_dir, verification)

        bundle_sha_after = sha256_path(bundle)
        if bundle_sha_after != bundle_sha_before:
            raise ImportErrorSafe(
                "bundle_changed_during_import",
                "incoming bundle changed during import",
                "$.bundle",
            )

        verification_path = tx_dir / "verification.json"
        write_json_atomic(verification_path, verification)

        release_metadata = {
            "release_schema_version": "1",
            "bundle_id": bundle_id,
            "bundle_sha256": bundle_sha_after,
            "manifest_sha256": verification["manifest_sha256"],
            "source": verification["source"],
            "payload_count": verification["payload_count"],
            "total_payload_bytes": verification["total_payload_bytes"],
            "state": "staged_not_active",
            "activated": False,
            "importer_version": IMPORTER_VERSION,
            "signature": verification.get("signature", {}),
        }

        schema = load_release_schema()
        errors = list(jsonschema.Draft202012Validator(schema).iter_errors(release_metadata))
        if errors:
            raise ImportErrorSafe(
                "release_metadata_schema_failed",
                "generated release metadata failed internal schema validation",
                "$",
                {"errors": [e.message for e in errors[:20]]},
            )

        write_json_atomic(tx_dir / "release.json", release_metadata)

        # Ensure directory contents reach the filesystem before the atomic
        # directory rename. This is durability hygiene, not activation.
        dir_fd = os.open(tx_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        os.rename(tx_dir, release_dir)
        committed = True

        event = {
            "event": "offline_bundle_imported",
            "bundle_id": bundle_id,
            "bundle_sha256": bundle_sha_after,
            "release_path": str(release_dir),
            "state": "staged_not_active",
            "activated": False,
            "importer_version": IMPORTER_VERSION,
            "epoch": int(time.time()),
        }
        append_event(event)

        return {
            "valid": True,
            "importer_version": IMPORTER_VERSION,
            "bundle_id": bundle_id,
            "bundle_sha256": bundle_sha_after,
            "release_path": str(release_dir),
            "payload_count": verification["payload_count"],
            "total_payload_bytes": verification["total_payload_bytes"],
            "state": "staged_not_active",
            "activated": False,
            "internet_access_performed": False,
            "shell_command_from_bundle_executed": False,
        }

    finally:
        if not committed and tx_dir.exists():
            shutil.rmtree(tx_dir)


def self_check() -> dict[str, Any]:
    return {
        "valid": True,
        "importer_version": IMPORTER_VERSION,
        "root": str(ROOT),
        "incoming": str(INCOMING),
        "staging": str(STAGING),
        "releases": str(RELEASES),
        "activation_performed": False,
        "internet_access_performed": False,
        "tar_extract_api_used": False,
        "bundle_commands_supported": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        emit(
            err_json(
                ImportErrorSafe(
                    "root_required",
                    "offline bundle import must run as root",
                )
            )
        )
        return 1

    try:
        if args.self_check:
            emit(self_check())
            return 0

        if args.bundle is None:
            raise ImportErrorSafe(
                "bundle_required",
                "--bundle is required unless --self-check is used",
            )

        emit(import_bundle(args.bundle))
        return 0

    except ImportErrorSafe as exc:
        emit(err_json(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
