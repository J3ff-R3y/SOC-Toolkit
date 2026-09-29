#!/usr/bin/env python3
"""
Jeffrey Toolkit — offline bundle offline update bundle verifier v1.

Security model:
- verifier only; no activation;
- server performs no internet request;
- archive is never extracted;
- manifest must fully declare every regular payload file;
- absolute/traversal/non-canonical paths are rejected;
- symlinks, hardlinks, devices, FIFO and other special entries are rejected;
- file count/size limits are enforced;
- every payload size + SHA256 is verified by streaming from the archive;
- detached OpenPGP signature can be required by local operator policy;
- no command/activation field exists in the manifest schema.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema

VERIFIER_VERSION = "offline-bundle-verifier-v1"

DEFAULT_SCHEMA = Path(
    "/opt/jeffrey-update/schemas/offline-update-manifest-v1.schema.json"
)

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
PAYLOAD_PREFIX = "payload/"

MAX_ARCHIVE_BYTES = 549755813888       # 512 GiB
MAX_MANIFEST_BYTES = 1048576           # 1 MiB
MAX_MEMBERS = 10050
MAX_PAYLOAD_FILES = 10000
MAX_PAYLOAD_FILE_BYTES = 274877906944  # 256 GiB
MAX_TOTAL_PAYLOAD_BYTES = 549755813888 # 512 GiB
CHUNK = 1024 * 1024


class VerifyError(Exception):
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


def error_json(exc: VerifyError) -> dict[str, Any]:
    out: dict[str, Any] = {
        "valid": False,
        "error": exc.code,
        "message": exc.message,
        "path": exc.path,
        "verifier_version": VERIFIER_VERSION,
    }
    if exc.details is not None:
        out["details"] = exc.details
    return out


def canonical_archive_path(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise VerifyError("invalid_archive_path", "archive entry path is empty")

    if "\x00" in name:
        raise VerifyError("invalid_archive_path", "archive entry contains NUL")

    if "\\" in name:
        raise VerifyError(
            "invalid_archive_path",
            "backslashes are not allowed in archive entry paths",
            name,
        )

    if name.startswith("/"):
        raise VerifyError(
            "absolute_path_rejected",
            "absolute archive paths are not allowed",
            name,
        )

    p = PurePosixPath(name)

    if any(part in {"", ".", ".."} for part in p.parts):
        raise VerifyError(
            "path_traversal_rejected",
            "archive path contains empty/dot/traversal component",
            name,
        )

    normalized = str(p)
    if normalized != name:
        raise VerifyError(
            "noncanonical_path",
            "archive path is not canonical",
            name,
        )

    return normalized


def safe_manifest_payload_path(value: str) -> str:
    name = canonical_archive_path(value)

    if not name.startswith(PAYLOAD_PREFIX):
        raise VerifyError(
            "invalid_payload_path",
            "manifest payload path must begin with payload/",
            f"$.payloads[path={value!r}]",
        )

    if name == PAYLOAD_PREFIX.rstrip("/") or name.endswith("/"):
        raise VerifyError(
            "invalid_payload_path",
            "manifest payload path must name a regular file",
            f"$.payloads[path={value!r}]",
        )

    return name


def load_schema(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(data)
        return data
    except Exception as exc:
        raise VerifyError(
            "schema_unavailable",
            f"manifest schema unavailable or invalid: {path}",
        ) from exc


def schema_errors(schema: dict[str, Any], obj: Any) -> list[dict[str, str]]:
    errs = list(jsonschema.Draft202012Validator(schema).iter_errors(obj))
    out = []
    for e in errs[:50]:
        path = "$"
        for part in e.path:
            if isinstance(part, int):
                path += f"[{part}]"
            else:
                path += f"[{json.dumps(part)}]"
        out.append({"path": path, "message": e.message})
    return out


def validate_manifest_semantics(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    payloads = manifest["payloads"]

    if len(payloads) > MAX_PAYLOAD_FILES:
        raise VerifyError(
            "payload_count_exceeded",
            f"manifest declares more than {MAX_PAYLOAD_FILES} payload files",
            "$.payloads",
        )

    declared: dict[str, dict[str, Any]] = {}
    total = 0

    for idx, item in enumerate(payloads):
        name = safe_manifest_payload_path(item["path"])

        if name in declared:
            raise VerifyError(
                "duplicate_manifest_path",
                "manifest declares the same payload path more than once",
                f"$.payloads[{idx}].path",
            )

        size = item["size"]
        if size > MAX_PAYLOAD_FILE_BYTES:
            raise VerifyError(
                "payload_file_too_large",
                f"payload exceeds {MAX_PAYLOAD_FILE_BYTES} bytes",
                f"$.payloads[{idx}].size",
            )

        total += size
        if total > MAX_TOTAL_PAYLOAD_BYTES:
            raise VerifyError(
                "payload_total_too_large",
                f"declared payload total exceeds {MAX_TOTAL_PAYLOAD_BYTES} bytes",
                "$.payloads",
            )

        declared[name] = item

    return declared


def inspect_members(tf: tarfile.TarFile) -> tuple[
    dict[str, tarfile.TarInfo],
    tarfile.TarInfo,
    tarfile.TarInfo | None,
]:
    members: dict[str, tarfile.TarInfo] = {}
    manifest_member: tarfile.TarInfo | None = None
    signature_member: tarfile.TarInfo | None = None
    count = 0

    for member in tf:
        count += 1
        if count > MAX_MEMBERS:
            raise VerifyError(
                "archive_member_limit",
                f"archive has more than {MAX_MEMBERS} members",
            )

        name = canonical_archive_path(member.name)

        if name in members:
            raise VerifyError(
                "duplicate_archive_path",
                "archive contains duplicate member path",
                name,
            )
        members[name] = member

        if member.issym():
            raise VerifyError("symlink_rejected", "symlink entry is forbidden", name)
        if member.islnk():
            raise VerifyError("hardlink_rejected", "hardlink entry is forbidden", name)
        if member.isdev():
            raise VerifyError("device_rejected", "device entry is forbidden", name)
        if member.isfifo():
            raise VerifyError("fifo_rejected", "FIFO entry is forbidden", name)
        if not (member.isfile() or member.isdir()):
            raise VerifyError(
                "special_file_rejected",
                "unsupported/special archive entry type",
                name,
            )

        if member.isfile() and member.size > MAX_PAYLOAD_FILE_BYTES:
            # manifest.json gets its tighter check below.
            if name != MANIFEST_NAME and name != SIGNATURE_NAME:
                raise VerifyError(
                    "archive_file_too_large",
                    f"archive member exceeds {MAX_PAYLOAD_FILE_BYTES} bytes",
                    name,
                )

        if name == MANIFEST_NAME:
            if not member.isfile():
                raise VerifyError(
                    "invalid_manifest_entry",
                    "manifest.json must be a regular file",
                    name,
                )
            manifest_member = member

        if name == SIGNATURE_NAME:
            if not member.isfile():
                raise VerifyError(
                    "invalid_signature_entry",
                    "manifest.sig must be a regular file",
                    name,
                )
            signature_member = member

    if manifest_member is None:
        raise VerifyError(
            "manifest_missing",
            "archive must contain manifest.json",
            "$",
        )

    return members, manifest_member, signature_member


def read_member_limited(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    limit: int,
) -> bytes:
    if member.size > limit:
        raise VerifyError(
            "member_too_large",
            f"{member.name} exceeds {limit} bytes",
            member.name,
        )

    fp = tf.extractfile(member)
    if fp is None:
        raise VerifyError(
            "member_unreadable",
            f"could not read archive member {member.name}",
            member.name,
        )

    data = fp.read(limit + 1)
    if len(data) > limit:
        raise VerifyError(
            "member_too_large",
            f"{member.name} exceeds {limit} bytes",
            member.name,
        )
    return data


def parse_manifest(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    schema: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    raw = read_member_limited(tf, member, MAX_MANIFEST_BYTES)

    try:
        manifest = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise VerifyError(
            "manifest_invalid_utf8",
            "manifest.json is not UTF-8",
            MANIFEST_NAME,
        ) from exc
    except json.JSONDecodeError as exc:
        raise VerifyError(
            "manifest_invalid_json",
            "manifest.json is not valid JSON",
            MANIFEST_NAME,
        ) from exc

    if not isinstance(manifest, dict):
        raise VerifyError(
            "manifest_invalid",
            "manifest must be a JSON object",
            "$",
        )

    errs = schema_errors(schema, manifest)
    if errs:
        raise VerifyError(
            "manifest_schema_failed",
            "manifest failed JSON Schema validation",
            "$",
            {"errors": errs},
        )

    return manifest, raw


def validate_archive_vs_manifest(
    members: dict[str, tarfile.TarInfo],
    declared: dict[str, dict[str, Any]],
) -> None:
    allowed_regular = set(declared)
    allowed_regular.add(MANIFEST_NAME)
    if SIGNATURE_NAME in members:
        allowed_regular.add(SIGNATURE_NAME)

    regular_names = {
        name
        for name, member in members.items()
        if member.isfile()
    }

    undeclared = sorted(regular_names - allowed_regular)
    if undeclared:
        raise VerifyError(
            "undeclared_file",
            "archive contains regular files not declared by the manifest",
            "$",
            {"paths": undeclared[:100]},
        )

    missing = sorted(set(declared) - regular_names)
    if missing:
        raise VerifyError(
            "declared_file_missing",
            "manifest declares payload files absent from archive",
            "$.payloads",
            {"paths": missing[:100]},
        )

    for name, member in members.items():
        if member.isdir():
            if name == "payload":
                continue
            if not name.startswith(PAYLOAD_PREFIX):
                raise VerifyError(
                    "unexpected_directory",
                    "archive directory is outside payload/",
                    name,
                )


def verify_payloads(
    tf: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    declared: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    verified = []
    total_actual = 0

    for name in sorted(declared):
        spec = declared[name]
        member = members[name]

        if not member.isfile():
            raise VerifyError(
                "payload_not_regular",
                "declared payload is not a regular file",
                name,
            )

        if member.size != spec["size"]:
            raise VerifyError(
                "size_mismatch",
                "payload size does not match manifest",
                name,
                {"expected": spec["size"], "actual": member.size},
            )

        fp = tf.extractfile(member)
        if fp is None:
            raise VerifyError(
                "payload_unreadable",
                "could not read payload",
                name,
            )

        h = hashlib.sha256()
        actual = 0

        while True:
            chunk = fp.read(CHUNK)
            if not chunk:
                break
            actual += len(chunk)
            if actual > spec["size"]:
                raise VerifyError(
                    "size_mismatch",
                    "payload stream exceeded declared size",
                    name,
                )
            h.update(chunk)

        if actual != spec["size"]:
            raise VerifyError(
                "size_mismatch",
                "payload bytes read do not match manifest",
                name,
                {"expected": spec["size"], "actual": actual},
            )

        digest = h.hexdigest()
        if digest != spec["sha256"]:
            raise VerifyError(
                "sha256_mismatch",
                "payload SHA256 does not match manifest",
                name,
                {"expected": spec["sha256"], "actual": digest},
            )

        total_actual += actual
        if total_actual > MAX_TOTAL_PAYLOAD_BYTES:
            raise VerifyError(
                "payload_total_too_large",
                "verified payload total exceeds configured limit",
                "$.payloads",
            )

        verified.append(
            {
                "path": name,
                "size": actual,
                "sha256": digest,
                "role": spec["role"],
            }
        )

    return verified


def verify_signature(
    tf: tarfile.TarFile,
    signature_member: tarfile.TarInfo | None,
    manifest_raw: bytes,
    policy: str,
    keyring: Path | None,
) -> dict[str, Any]:
    present = signature_member is not None

    if policy == "sha256":
        return {
            "policy": "sha256",
            "present": present,
            "verified": False,
            "reason": "detached signature not required by current local policy",
        }

    if policy != "gpgv-required":
        raise VerifyError(
            "invalid_signature_policy",
            "unsupported signature policy",
            "$",
        )

    if signature_member is None:
        raise VerifyError(
            "signature_required",
            "local policy requires manifest.sig",
            SIGNATURE_NAME,
        )

    if keyring is None:
        raise VerifyError(
            "keyring_required",
            "--keyring is required with gpgv-required policy",
            "$",
        )

    if not keyring.is_file():
        raise VerifyError(
            "keyring_unavailable",
            f"approved keyring does not exist: {keyring}",
            "$",
        )

    signature_raw = read_member_limited(tf, signature_member, MAX_MANIFEST_BYTES)

    gpgv = Path("/usr/bin/gpgv")
    if not gpgv.exists():
        gpgv = Path("/bin/gpgv")
    if not gpgv.exists():
        raise VerifyError(
            "gpgv_unavailable",
            "gpgv is not installed",
            "$",
        )

    with tempfile.TemporaryDirectory(prefix="jeffrey-offline-update-gpgv-") as td:
        manifest_path = Path(td) / MANIFEST_NAME
        sig_path = Path(td) / SIGNATURE_NAME
        manifest_path.write_bytes(manifest_raw)
        sig_path.write_bytes(signature_raw)
        os.chmod(manifest_path, 0o600)
        os.chmod(sig_path, 0o600)

        proc = subprocess.run(
            [
                str(gpgv),
                "--keyring",
                str(keyring),
                str(sig_path),
                str(manifest_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            check=False,
        )

    if proc.returncode != 0:
        raise VerifyError(
            "signature_invalid",
            "gpgv did not validate manifest.sig against the approved keyring",
            SIGNATURE_NAME,
            {"gpgv_returncode": proc.returncode},
        )

    return {
        "policy": "gpgv-required",
        "present": True,
        "verified": True,
    }


def verify_bundle(
    archive_path: Path,
    schema_path: Path,
    signature_policy: str,
    keyring: Path | None,
) -> dict[str, Any]:
    try:
        st = archive_path.lstat()
    except FileNotFoundError as exc:
        raise VerifyError(
            "bundle_missing",
            f"bundle not found: {archive_path}",
            "$",
        ) from exc

    if archive_path.is_symlink():
        raise VerifyError(
            "bundle_symlink_rejected",
            "bundle path itself must not be a symlink",
            "$",
        )

    if not archive_path.is_file():
        raise VerifyError(
            "bundle_not_regular",
            "bundle path must be a regular file",
            "$",
        )

    if st.st_size > MAX_ARCHIVE_BYTES:
        raise VerifyError(
            "bundle_too_large",
            f"archive exceeds {MAX_ARCHIVE_BYTES} bytes",
            "$",
        )

    schema = load_schema(schema_path)

    try:
        tf = tarfile.open(archive_path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise VerifyError(
            "invalid_archive",
            "bundle is not a readable tar archive",
            "$",
        ) from exc

    with tf:
        members, manifest_member, signature_member = inspect_members(tf)
        manifest, manifest_raw = parse_manifest(tf, manifest_member, schema)
        declared = validate_manifest_semantics(manifest)
        validate_archive_vs_manifest(members, declared)

        signature = verify_signature(
            tf,
            signature_member,
            manifest_raw,
            signature_policy,
            keyring,
        )

        verified_payloads = verify_payloads(tf, members, declared)

    manifest_hash = hashlib.sha256(manifest_raw).hexdigest()

    return {
        "valid": True,
        "verifier_version": VERIFIER_VERSION,
        "bundle_format": manifest["bundle_format"],
        "schema_version": manifest["schema_version"],
        "bundle_id": manifest["bundle_id"],
        "source": manifest["source"],
        "manifest_sha256": manifest_hash,
        "payload_count": len(verified_payloads),
        "total_payload_bytes": sum(x["size"] for x in verified_payloads),
        "payloads": verified_payloads,
        "signature": signature,
        "activation_performed": False,
        "internet_access_performed": False,
    }


def self_check(schema_path: Path) -> dict[str, Any]:
    schema = load_schema(schema_path)
    return {
        "valid": True,
        "verifier_version": VERIFIER_VERSION,
        "schema_id": schema.get("$id"),
        "archive_extraction": False,
        "activation_performed": False,
        "internet_access_performed": False,
        "signature_policies": ["sha256", "gpgv-required"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--signature-policy",
        choices=("sha256", "gpgv-required"),
        default="sha256",
    )
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_check:
            emit(self_check(args.schema))
            return 0

        if args.bundle is None:
            raise VerifyError(
                "bundle_required",
                "--bundle is required unless --self-check is used",
                "$",
            )

        result = verify_bundle(
            args.bundle,
            args.schema,
            args.signature_policy,
            args.keyring,
        )
        emit(result)
        return 0

    except VerifyError as exc:
        emit(error_json(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
