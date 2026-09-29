#!/usr/bin/env python3
"""
Jeffrey Toolkit — release activation source-specific activation manager v1.

Scope:
- activates only knowledge-class staged releases through atomic versioned pointers;
- model/runtime/frontend/other source classes are explicitly blocked;
- validates staged release integrity immediately before activation/rollback;
- no service reload/restart;
- no network access;
- no bundle-supplied command execution;
- active symlink is authoritative; JSON state/history provide audit/rollback data.

This does not yet wire Jeffrey application consumers to the active pointers.
That integration remains source-specific and must be explicit.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema

MANAGER_VERSION = "activation-manager-v1"

ROOT = Path("/data/jeffrey-updates")
RELEASES = ROOT / "releases"
ACTIVE = ROOT / "active"
STATE = ROOT / "state"
LOGS = ROOT / "logs"

POLICY_PATH = Path("/opt/jeffrey-update/etc/offline-update-policy-v1.json")
STATE_SCHEMA_PATH = Path("/opt/jeffrey-update/schemas/activation-state-v1.schema.json")
RELEASE_SCHEMA_PATH = Path("/opt/jeffrey-update/schemas/offline-release-v1.schema.json")

BUNDLE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CHUNK = 1024 * 1024


class ActivationError(Exception):
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


def error_json(exc: ActivationError) -> dict[str, Any]:
    out: dict[str, Any] = {
        "valid": False,
        "error": exc.code,
        "message": exc.message,
        "path": exc.path,
        "manager_version": MANAGER_VERSION,
    }
    if exc.details is not None:
        out["details"] = exc.details
    return out


def load_json(path: Path, code: str) -> dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ActivationError(code, f"could not load JSON: {path}") from exc
    if not isinstance(obj, dict):
        raise ActivationError(code, f"JSON root must be object: {path}")
    return obj


def load_schema(path: Path, code: str) -> dict[str, Any]:
    obj = load_json(path, code)
    try:
        jsonschema.Draft202012Validator.check_schema(obj)
    except Exception as exc:
        raise ActivationError(code, f"invalid JSON schema: {path}") from exc
    return obj


def validate_json(schema: dict[str, Any], obj: Any, code: str, label: str) -> None:
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(obj))
    if errors:
        details = []
        for e in errors[:30]:
            p = "$"
            for part in e.path:
                p += f"[{part!r}]"
            details.append({"path": p, "message": e.message})
        raise ActivationError(
            code,
            f"{label} failed JSON Schema validation",
            "$",
            {"errors": details},
        )


def require_layout() -> None:
    for path in (ROOT, RELEASES, ACTIVE, STATE, LOGS):
        try:
            st = path.lstat()
        except FileNotFoundError as exc:
            raise ActivationError(
                "layout_missing",
                f"required release activation path is missing: {path}",
            ) from exc

        if path.is_symlink() or not path.is_dir():
            raise ActivationError(
                "unsafe_layout",
                f"required path is not a real directory: {path}",
            )

        if st.st_uid != 0:
            raise ActivationError(
                "unsafe_layout_owner",
                f"required path must be root-owned: {path}",
            )

        if st.st_mode & 0o022:
            raise ActivationError(
                "unsafe_layout_permissions",
                f"required path must not be group/world writable: {path}",
            )


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def safe_bundle_id(bundle_id: str) -> str:
    if not BUNDLE_ID_RE.fullmatch(bundle_id):
        raise ActivationError(
            "invalid_bundle_id",
            "bundle_id is not a canonical UUID",
            "$.bundle_id",
        )
    return bundle_id


def safe_payload_path(name: str) -> Path:
    p = PurePosixPath(name)
    if (
        not name.startswith("payload/")
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in p.parts)
        or str(p) != name
    ):
        raise ActivationError(
            "release_integrity_failed",
            "verification metadata contains unsafe payload path",
            name,
        )
    return Path(*p.parts)


def assert_safe_tree(release_dir: Path, expected_files: set[str]) -> None:
    found_files: set[str] = set()

    for root, dirs, files in os.walk(release_dir, followlinks=False):
        root_path = Path(root)

        for d in dirs:
            p = root_path / d
            st = p.lstat()
            if p.is_symlink():
                raise ActivationError(
                    "release_integrity_failed",
                    "release contains symlink directory",
                    str(p),
                )
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise ActivationError(
                    "release_integrity_failed",
                    "release directory ownership/permissions are unsafe",
                    str(p),
                )

        for name in files:
            p = root_path / name
            rel = p.relative_to(release_dir).as_posix()
            st = p.lstat()

            if p.is_symlink() or not p.is_file():
                raise ActivationError(
                    "release_integrity_failed",
                    "release contains non-regular file",
                    rel,
                )
            if st.st_nlink != 1:
                raise ActivationError(
                    "release_integrity_failed",
                    "release contains hard-linked file",
                    rel,
                )
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise ActivationError(
                    "release_integrity_failed",
                    "release file ownership/permissions are unsafe",
                    rel,
                )

            found_files.add(rel)

    unexpected = sorted(found_files - expected_files)
    missing = sorted(expected_files - found_files)

    if unexpected or missing:
        raise ActivationError(
            "release_integrity_failed",
            "release file set differs from verified/imported file set",
            str(release_dir),
            {
                "unexpected": unexpected[:100],
                "missing": missing[:100],
            },
        )


def validate_release(bundle_id: str) -> dict[str, Any]:
    bundle_id = safe_bundle_id(bundle_id)
    release_dir = RELEASES / bundle_id

    if not release_dir.exists() or release_dir.is_symlink() or not release_dir.is_dir():
        raise ActivationError(
            "release_missing",
            f"staged release does not exist: {bundle_id}",
            "$.bundle_id",
        )

    st = release_dir.lstat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ActivationError(
            "release_integrity_failed",
            "release directory ownership/permissions are unsafe",
            str(release_dir),
        )

    release_json = release_dir / "release.json"
    verification_json = release_dir / "verification.json"
    manifest_json = release_dir / "manifest.json"

    for path in (release_json, verification_json, manifest_json):
        if not path.is_file() or path.is_symlink():
            raise ActivationError(
                "release_integrity_failed",
                f"required release metadata missing/unsafe: {path.name}",
                str(path),
            )

    release = load_json(release_json, "release_integrity_failed")
    verification = load_json(verification_json, "release_integrity_failed")

    release_schema = load_schema(RELEASE_SCHEMA_PATH, "release_schema_unavailable")
    validate_json(
        release_schema,
        release,
        "release_integrity_failed",
        "release.json",
    )

    if release.get("bundle_id") != bundle_id:
        raise ActivationError(
            "release_integrity_failed",
            "release.json bundle_id does not match directory name",
            str(release_json),
        )

    if verification.get("valid") is not True:
        raise ActivationError(
            "release_integrity_failed",
            "verification.json is not a successful bundle verifier result",
            str(verification_json),
        )

    if verification.get("bundle_id") != bundle_id:
        raise ActivationError(
            "release_integrity_failed",
            "verification bundle_id mismatch",
            str(verification_json),
        )

    if release.get("manifest_sha256") != verification.get("manifest_sha256"):
        raise ActivationError(
            "release_integrity_failed",
            "release/verification manifest hash mismatch",
        )

    if sha256_path(manifest_json) != verification.get("manifest_sha256"):
        raise ActivationError(
            "release_integrity_failed",
            "manifest.json SHA256 differs from verified value",
            str(manifest_json),
        )

    payloads = verification.get("payloads")
    if not isinstance(payloads, list) or not payloads:
        raise ActivationError(
            "release_integrity_failed",
            "verification contains no payload list",
            str(verification_json),
        )

    expected = {
        "manifest.json",
        "verification.json",
        "release.json",
    }

    sig = release_dir / "manifest.sig"
    if sig.exists():
        expected.add("manifest.sig")

    total = 0
    for item in payloads:
        if not isinstance(item, dict):
            raise ActivationError(
                "release_integrity_failed",
                "invalid payload verification item",
            )

        name = item.get("path")
        size = item.get("size")
        sha = item.get("sha256")

        if not isinstance(name, str):
            raise ActivationError(
                "release_integrity_failed",
                "payload path missing from verification",
            )

        rel = safe_payload_path(name)
        expected.add(rel.as_posix())

        path = release_dir / rel
        if not path.is_file() or path.is_symlink():
            raise ActivationError(
                "release_integrity_failed",
                "verified payload missing or unsafe",
                name,
            )

        st = path.lstat()
        if st.st_nlink != 1:
            raise ActivationError(
                "release_integrity_failed",
                "verified payload has unexpected hardlink count",
                name,
            )

        if st.st_size != size:
            raise ActivationError(
                "release_integrity_failed",
                "verified payload size changed after import",
                name,
            )

        digest = sha256_path(path)
        if digest != sha:
            raise ActivationError(
                "release_integrity_failed",
                "verified payload SHA256 changed after import",
                name,
            )

        total += st.st_size

    if total != verification.get("total_payload_bytes"):
        raise ActivationError(
            "release_integrity_failed",
            "verified total payload byte count mismatch",
        )

    if len(payloads) != verification.get("payload_count"):
        raise ActivationError(
            "release_integrity_failed",
            "verified payload count mismatch",
        )

    assert_safe_tree(release_dir, expected)

    return {
        "bundle_id": bundle_id,
        "release_dir": release_dir,
        "release": release,
        "verification": verification,
        "source_type": release["source"]["type"],
    }


def load_policy() -> dict[str, Any]:
    policy = load_json(POLICY_PATH, "activation_policy_unavailable")

    if policy.get("policy_version") != "offline-update-policy-v1":
        raise ActivationError(
            "activation_policy_unavailable",
            "unsupported activation policy version",
        )

    return policy


def adapter_for(source_type: str, policy: dict[str, Any]) -> dict[str, Any]:
    adapters = policy.get("source_adapters")
    if not isinstance(adapters, dict) or source_type not in adapters:
        raise ActivationError(
            "source_type_not_configured",
            f"source type is not configured: {source_type}",
        )

    adapter = adapters[source_type]
    if not isinstance(adapter, dict):
        raise ActivationError(
            "activation_policy_unavailable",
            "invalid source adapter configuration",
        )
    return adapter


def symlink_bundle(slot: str) -> str | None:
    link = ACTIVE / slot
    if not link.exists() and not link.is_symlink():
        return None

    if not link.is_symlink():
        raise ActivationError(
            "active_pointer_unsafe",
            f"active slot is not a symlink: {link}",
        )

    target = os.readlink(link)
    prefix = "../releases/"
    if not target.startswith(prefix):
        raise ActivationError(
            "active_pointer_unsafe",
            "active pointer target is outside releases",
            str(link),
        )

    bundle_id = target[len(prefix):]
    safe_bundle_id(bundle_id)

    if "/" in bundle_id or "\\" in bundle_id:
        raise ActivationError(
            "active_pointer_unsafe",
            "active pointer has invalid target",
            str(link),
        )

    return bundle_id


def load_state(slot: str) -> dict[str, Any] | None:
    path = STATE / f"{slot}.json"
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ActivationError(
            "activation_state_unsafe",
            f"activation state is not a regular file: {path}",
        )

    obj = load_json(path, "activation_state_invalid")
    schema = load_schema(STATE_SCHEMA_PATH, "activation_state_schema_unavailable")
    validate_json(schema, obj, "activation_state_invalid", path.name)
    return obj


def write_json_atomic(path: Path, obj: dict[str, Any]) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(tmp, flags, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def append_history(event: dict[str, Any]) -> None:
    path = LOGS / "activation-history.jsonl"
    line = json.dumps(event, sort_keys=True) + "\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def atomic_switch(slot: str, bundle_id: str) -> None:
    link = ACTIVE / slot
    temp = ACTIVE / f".{slot}.{os.getpid()}.tmp"
    target = f"../releases/{bundle_id}"

    if temp.exists() or temp.is_symlink():
        temp.unlink()

    os.symlink(target, temp)
    os.replace(temp, link)

    fd = os.open(ACTIVE, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def with_lock() -> Any:
    lock_path = STATE / ".activation.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    f = os.fdopen(fd, "r+")
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    return f


def plan(bundle_id: str) -> dict[str, Any]:
    info = validate_release(bundle_id)
    policy = load_policy()
    adapter = adapter_for(info["source_type"], policy)

    allowed = adapter.get("mode") == "versioned_pointer"

    return {
        "valid": True,
        "manager_version": MANAGER_VERSION,
        "operation": "plan",
        "bundle_id": bundle_id,
        "source_type": info["source_type"],
        "activation_allowed": allowed,
        "mode": adapter.get("mode"),
        "slot": adapter.get("slot"),
        "consumer_reload": adapter.get("consumer_reload", "none"),
        "reason": adapter.get("reason"),
        "release_integrity_valid": True,
        "service_restart_planned": False,
        "internet_access_performed": False,
    }


def activate(bundle_id: str) -> dict[str, Any]:
    info = validate_release(bundle_id)
    policy = load_policy()
    adapter = adapter_for(info["source_type"], policy)

    if adapter.get("mode") != "versioned_pointer":
        raise ActivationError(
            "activation_not_supported",
            "this source type is not eligible for automatic release activation activation",
            "$.bundle_id",
            {
                "source_type": info["source_type"],
                "mode": adapter.get("mode"),
                "reason": adapter.get("reason"),
            },
        )

    slot = adapter.get("slot")
    if not isinstance(slot, str) or not slot:
        raise ActivationError(
            "activation_policy_unavailable",
            "allowed adapter has no valid slot",
        )

    with with_lock():
        current = symlink_bundle(slot)
        old_state = load_state(slot)

        if current == bundle_id:
            return {
                "valid": True,
                "manager_version": MANAGER_VERSION,
                "operation": "activate",
                "slot": slot,
                "active_bundle_id": bundle_id,
                "previous_bundle_id": old_state.get("previous_bundle_id") if old_state else None,
                "changed": False,
                "consumer_reload": "none",
                "service_restart_performed": False,
                "internet_access_performed": False,
            }

        generation = 1
        if old_state is not None:
            generation = int(old_state["generation"]) + 1

        atomic_switch(slot, bundle_id)

        state = {
            "activation_state_version": "1",
            "slot": slot,
            "active_bundle_id": bundle_id,
            "previous_bundle_id": current,
            "source_type": info["source_type"],
            "generation": generation,
            "changed_at_epoch": int(time.time()),
            "manager_version": MANAGER_VERSION,
            "consumer_reload": "none",
        }

        schema = load_schema(STATE_SCHEMA_PATH, "activation_state_schema_unavailable")
        validate_json(schema, state, "activation_state_invalid", "generated activation state")
        write_json_atomic(STATE / f"{slot}.json", state)

        append_history(
            {
                "event": "activate",
                "slot": slot,
                "active_bundle_id": bundle_id,
                "previous_bundle_id": current,
                "generation": generation,
                "source_type": info["source_type"],
                "epoch": int(time.time()),
                "manager_version": MANAGER_VERSION,
            }
        )

    return {
        "valid": True,
        "manager_version": MANAGER_VERSION,
        "operation": "activate",
        "slot": slot,
        "active_bundle_id": bundle_id,
        "previous_bundle_id": current,
        "changed": True,
        "consumer_reload": "none",
        "service_restart_performed": False,
        "internet_access_performed": False,
    }


def status(slot: str) -> dict[str, Any]:
    policy = load_policy()
    allowed_slots = set(policy.get("allowed_slots", []))
    if slot not in allowed_slots:
        raise ActivationError(
            "slot_not_allowed",
            "slot is not in the configured allowlist",
            "$.slot",
        )

    current = symlink_bundle(slot)
    state = load_state(slot)

    consistent = True
    if state is not None:
        consistent = state["active_bundle_id"] == current
    elif current is not None:
        consistent = False

    return {
        "valid": True,
        "manager_version": MANAGER_VERSION,
        "operation": "status",
        "slot": slot,
        "active_bundle_id": current,
        "state": state,
        "consistent": consistent,
        "service_restart_performed": False,
        "internet_access_performed": False,
    }


def rollback(slot: str) -> dict[str, Any]:
    policy = load_policy()
    allowed_slots = set(policy.get("allowed_slots", []))
    if slot not in allowed_slots:
        raise ActivationError(
            "slot_not_allowed",
            "slot is not in the configured allowlist",
            "$.slot",
        )

    with with_lock():
        current = symlink_bundle(slot)
        state = load_state(slot)

        if current is None or state is None:
            raise ActivationError(
                "rollback_unavailable",
                "slot has no active state to roll back",
                "$.slot",
            )

        if state["active_bundle_id"] != current:
            raise ActivationError(
                "activation_state_mismatch",
                "active pointer and state metadata disagree",
                "$.slot",
            )

        previous = state.get("previous_bundle_id")
        if not previous:
            raise ActivationError(
                "rollback_unavailable",
                "slot has no previous bundle",
                "$.slot",
            )

        info = validate_release(previous)
        adapter = adapter_for(info["source_type"], policy)

        if adapter.get("mode") != "versioned_pointer" or adapter.get("slot") != slot:
            raise ActivationError(
                "rollback_target_invalid",
                "previous release is not eligible for this slot",
                "$.slot",
            )

        generation = int(state["generation"]) + 1
        atomic_switch(slot, previous)

        new_state = {
            "activation_state_version": "1",
            "slot": slot,
            "active_bundle_id": previous,
            "previous_bundle_id": current,
            "source_type": info["source_type"],
            "generation": generation,
            "changed_at_epoch": int(time.time()),
            "manager_version": MANAGER_VERSION,
            "consumer_reload": "none",
        }

        schema = load_schema(STATE_SCHEMA_PATH, "activation_state_schema_unavailable")
        validate_json(schema, new_state, "activation_state_invalid", "generated rollback state")
        write_json_atomic(STATE / f"{slot}.json", new_state)

        append_history(
            {
                "event": "rollback",
                "slot": slot,
                "active_bundle_id": previous,
                "previous_bundle_id": current,
                "generation": generation,
                "source_type": info["source_type"],
                "epoch": int(time.time()),
                "manager_version": MANAGER_VERSION,
            }
        )

    return {
        "valid": True,
        "manager_version": MANAGER_VERSION,
        "operation": "rollback",
        "slot": slot,
        "active_bundle_id": previous,
        "previous_bundle_id": current,
        "changed": True,
        "consumer_reload": "none",
        "service_restart_performed": False,
        "internet_access_performed": False,
    }


def self_check() -> dict[str, Any]:
    policy = load_policy()
    return {
        "valid": True,
        "manager_version": MANAGER_VERSION,
        "automatic_source_types": sorted(
            k for k, v in policy["source_adapters"].items()
            if v.get("mode") == "versioned_pointer"
        ),
        "blocked_source_types": sorted(
            k for k, v in policy["source_adapters"].items()
            if v.get("mode") != "versioned_pointer"
        ),
        "allowed_slots": policy["allowed_slots"],
        "consumer_reload": "none",
        "service_restart_performed": False,
        "internet_access_performed": False,
        "bundle_commands_supported": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", metavar="BUNDLE_ID")
    group.add_argument("--activate", metavar="BUNDLE_ID")
    group.add_argument("--status", metavar="SLOT")
    group.add_argument("--rollback", metavar="SLOT")
    group.add_argument("--self-check", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        emit(error_json(ActivationError("root_required", "activation manager must run as root")))
        return 1

    try:
        require_layout()

        if args.self_check:
            emit(self_check())
        elif args.plan:
            emit(plan(args.plan))
        elif args.activate:
            emit(activate(args.activate))
        elif args.status:
            emit(status(args.status))
        elif args.rollback:
            emit(rollback(args.rollback))
        else:
            raise ActivationError("invalid_operation", "no operation selected")
        return 0

    except ActivationError as exc:
        emit(error_json(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
