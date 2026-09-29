#!/usr/bin/env python3
"""
Jeffrey Toolkit — static-forensics deterministic static-forensics backend v1.

Static-only design:
- no sample execution;
- no shell=True;
- no unpack/extract of archives;
- source is opened with O_NOFOLLOW and copied to a private snapshot;
- fixed external command argv only;
- bounded file size, output size, timeouts, strings and metadata lists.

The backend is intentionally an evidence extractor, not an IOC verdict engine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

BACKEND_VERSION = "static-forensics-v1"
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MAX_TOOL_OUTPUT = 512 * 1024
TOOL_TIMEOUT = 15
MAX_STRINGS = 100
MAX_STRING_LEN = 300


class AnalysisError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def fail(code: str, message: str) -> dict[str, Any]:
    return {
        "valid": False,
        "error": code,
        "message": message,
        "backend_version": BACKEND_VERSION,
    }


def run_tool(argv: list[str], warnings: list[str], used: list[str]) -> str:
    exe = shutil.which(argv[0])
    if exe is None:
        warnings.append(f"tool unavailable: {argv[0]}")
        return ""

    command = [exe, *argv[1:]]
    used.append(Path(exe).name)
    try:
        proc = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=TOOL_TIMEOUT,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        warnings.append(f"tool timeout: {Path(exe).name}")
        return ""
    except Exception as exc:
        warnings.append(f"tool failed: {Path(exe).name}: {type(exc).__name__}")
        return ""

    raw = proc.stdout[:MAX_TOOL_OUTPUT]
    if len(proc.stdout) > MAX_TOOL_OUTPUT:
        warnings.append(f"tool output truncated: {Path(exe).name}")

    if proc.returncode not in (0, 1):
        warnings.append(f"tool returned rc={proc.returncode}: {Path(exe).name}")

    return raw.decode("utf-8", errors="replace")


def snapshot_source(source: Path, max_bytes: int, temp_dir: Path) -> tuple[Path, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        fd = os.open(source, flags)
    except FileNotFoundError as exc:
        raise AnalysisError("not_found", "input file does not exist") from exc
    except OSError as exc:
        raise AnalysisError("open_failed", f"input could not be opened safely: {exc.strerror}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AnalysisError("not_regular_file", "input must be a regular file")
        if st.st_size > max_bytes:
            raise AnalysisError("file_too_large", f"input exceeds maximum of {max_bytes} bytes")

        dest = temp_dir / "sample.bin"
        total = 0
        with os.fdopen(fd, "rb", closefd=False) as src, open(dest, "wb") as out:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise AnalysisError("file_too_large", f"input exceeds maximum of {max_bytes} bytes")
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())

        os.chmod(dest, 0o600)
        return dest, total
    finally:
        os.close(fd)


def hash_file(path: Path) -> dict[str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def magic_info(path: Path, warnings: list[str], used: list[str]) -> tuple[str, str]:
    description = run_tool(["file", "-b", "--", str(path)], warnings, used).strip()
    mime = run_tool(["file", "-b", "--mime-type", "--", str(path)], warnings, used).strip()
    return description[:2000], mime[:500]


def detect_kind(path: Path, mime: str) -> str:
    with path.open("rb") as f:
        head = f.read(4096)

    if head.startswith(b"\x7fELF"):
        return "elf"

    if head.startswith(b"MZ") and len(head) >= 0x40:
        try:
            pe_off = struct.unpack_from("<I", head, 0x3C)[0]
            if pe_off + 4 <= len(head):
                if head[pe_off:pe_off+4] == b"PE\x00\x00":
                    return "pe"
            else:
                with path.open("rb") as f:
                    f.seek(pe_off)
                    if f.read(4) == b"PE\x00\x00":
                        return "pe"
        except Exception:
            pass

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return "zip"

    if head.startswith(b"%PDF-"):
        return "pdf"

    if mime.startswith("text/"):
        return "text"

    # Conservative heuristic for small mostly printable files when file(1)
    # is unavailable or reports generic data.
    sample = head[:2048]
    if sample:
        printable = sum(1 for b in sample if b in b"\t\n\r" or 32 <= b <= 126)
        if printable / len(sample) >= 0.90:
            return "text"

    return "unknown"


def strings_sample(path: Path, warnings: list[str], used: list[str]) -> list[str]:
    text = run_tool(["strings", "-a", "-n", "6", "--", str(path)], warnings, used)
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line[:MAX_STRING_LEN])
        if len(out) >= MAX_STRINGS:
            break
    return out


def parse_elf(path: Path, warnings: list[str], used: list[str]) -> dict[str, Any]:
    with path.open("rb") as f:
        ident = f.read(16)
        if len(ident) < 16 or ident[:4] != b"\x7fELF":
            raise AnalysisError("elf_parse_failed", "invalid ELF identification")

        ei_class = ident[4]
        ei_data = ident[5]
        endian = "<" if ei_data == 1 else ">" if ei_data == 2 else None
        if endian is None:
            raise AnalysisError("elf_parse_failed", "unsupported ELF endianness")

        if ei_class == 1:
            fmt = endian + "HHIIIIIHHHHHH"
            raw = f.read(struct.calcsize(fmt))
            if len(raw) != struct.calcsize(fmt):
                raise AnalysisError("elf_parse_failed", "truncated ELF32 header")
            vals = struct.unpack(fmt, raw)
            elf_class = "ELF32"
            e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = vals
        elif ei_class == 2:
            fmt = endian + "HHIQQQIHHHHHH"
            raw = f.read(struct.calcsize(fmt))
            if len(raw) != struct.calcsize(fmt):
                raise AnalysisError("elf_parse_failed", "truncated ELF64 header")
            vals = struct.unpack(fmt, raw)
            elf_class = "ELF64"
            e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = vals
        else:
            raise AnalysisError("elf_parse_failed", "unsupported ELF class")

    dyn = run_tool(["readelf", "-dW", str(path)], warnings, used)
    needed: list[str] = []
    for m in re.finditer(r"\(NEEDED\).*Shared library: \[(.*?)\]", dyn):
        value = m.group(1)[:500]
        if value not in needed:
            needed.append(value)
        if len(needed) >= 128:
            break

    syms = run_tool(["readelf", "-Ws", str(path)], warnings, used)
    undefined: list[str] = []
    for line in syms.splitlines():
        if " UND " not in f" {line} ":
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        if name and name != "UND" and name not in undefined:
            undefined.append(name[:500])
        if len(undefined) >= 256:
            break

    return {
        "class": elf_class,
        "endian": "little" if endian == "<" else "big",
        "type": int(e_type),
        "machine": int(e_machine),
        "entry_point": int(e_entry),
        "program_headers": int(e_phnum),
        "section_headers": int(e_shnum),
        "needed_libraries": needed,
        "undefined_symbols": undefined,
    }


def parse_pe(path: Path, warnings: list[str], used: list[str]) -> dict[str, Any]:
    with path.open("rb") as f:
        dos = f.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise AnalysisError("pe_parse_failed", "invalid DOS header")
        pe_off = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_off < 64 or pe_off > 16 * 1024 * 1024:
            raise AnalysisError("pe_parse_failed", "invalid PE header offset")
        f.seek(pe_off)
        if f.read(4) != b"PE\x00\x00":
            raise AnalysisError("pe_parse_failed", "missing PE signature")

        coff = f.read(20)
        if len(coff) != 20:
            raise AnalysisError("pe_parse_failed", "truncated COFF header")
        machine, sections, timestamp, _, _, opt_size, characteristics = struct.unpack("<HHIIIHH", coff)

        opt = f.read(opt_size)
        if len(opt) != opt_size or opt_size < 2:
            raise AnalysisError("pe_parse_failed", "truncated PE optional header")

        optional_magic = struct.unpack_from("<H", opt, 0)[0]
        entry_point = struct.unpack_from("<I", opt, 16)[0] if len(opt) >= 20 else 0

        if optional_magic == 0x10B:  # PE32
            image_base = struct.unpack_from("<I", opt, 28)[0] if len(opt) >= 32 else 0
            subsystem = struct.unpack_from("<H", opt, 68)[0] if len(opt) >= 70 else 0
            dll_characteristics = struct.unpack_from("<H", opt, 70)[0] if len(opt) >= 72 else 0
        elif optional_magic == 0x20B:  # PE32+
            image_base = struct.unpack_from("<Q", opt, 24)[0] if len(opt) >= 32 else 0
            subsystem = struct.unpack_from("<H", opt, 68)[0] if len(opt) >= 70 else 0
            dll_characteristics = struct.unpack_from("<H", opt, 70)[0] if len(opt) >= 72 else 0
        else:
            image_base = 0
            subsystem = 0
            dll_characteristics = 0

    objdump = run_tool(["objdump", "-p", str(path)], warnings, used)
    dlls: list[str] = []
    for line in objdump.splitlines():
        m = re.search(r"DLL Name:\s*(.+)$", line)
        if m:
            name = m.group(1).strip()[:500]
            if name and name not in dlls:
                dlls.append(name)
            if len(dlls) >= 128:
                break

    return {
        "machine": int(machine),
        "sections": int(sections),
        "timestamp": int(timestamp),
        "characteristics": int(characteristics),
        "optional_magic": int(optional_magic),
        "entry_point": int(entry_point),
        "image_base": int(image_base),
        "subsystem": int(subsystem),
        "dll_characteristics": int(dll_characteristics),
        "imported_dlls": dlls,
    }


def safe_zip_name(name: str) -> bool:
    # Normalize both common separators before checking.
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    if p.is_absolute():
        return False
    parts = p.parts
    if any(part == ".." for part in parts):
        return False
    # Windows drive-form path inside archive.
    if re.match(r"^[A-Za-z]:", normalized):
        return False
    return True


def parse_zip(path: Path, warnings: list[str]) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            sample = [zi.filename[:500] for zi in infos[:100]]
            traversal = [zi.filename[:500] for zi in infos if not safe_zip_name(zi.filename)][:100]
            return {
                "entry_count": len(infos),
                "entries_sample": sample,
                "path_traversal_entries": traversal,
            }
    except (zipfile.BadZipFile, OSError) as exc:
        warnings.append(f"zip parse failed: {type(exc).__name__}")
        return {
            "entry_count": 0,
            "entries_sample": [],
            "path_traversal_entries": [],
        }


def analyze(source: Path, max_bytes: int) -> dict[str, Any]:
    warnings: list[str] = []
    used: list[str] = []

    with tempfile.TemporaryDirectory(prefix="jeffrey-forensics-") as td:
        temp_dir = Path(td)
        snapshot, size = snapshot_source(source, max_bytes, temp_dir)

        hashes = hash_file(snapshot)
        description, mime = magic_info(snapshot, warnings, used)
        kind = detect_kind(snapshot, mime)
        sample_strings = strings_sample(snapshot, warnings, used)

        elf = None
        pe = None
        zip_info = None

        if kind == "elf":
            try:
                elf = parse_elf(snapshot, warnings, used)
            except AnalysisError as exc:
                warnings.append(f"{exc.code}: {exc.message}")
        elif kind == "pe":
            try:
                pe = parse_pe(snapshot, warnings, used)
            except AnalysisError as exc:
                warnings.append(f"{exc.code}: {exc.message}")
        elif kind == "zip":
            zip_info = parse_zip(snapshot, warnings)

        return {
            "artifact_type": "forensics_static",
            "schema_version": "1",
            "backend_version": BACKEND_VERSION,
            "source_name": source.name[:255] or "unnamed",
            "size_bytes": size,
            "hashes": hashes,
            "file_type": {
                "kind": kind,
                "description": description,
                "mime": mime,
            },
            "strings_sample": sample_strings,
            "elf": elf,
            "pe": pe,
            "zip": zip_info,
            "analysis": {
                "static_only": True,
                "executed": False,
                "snapshot_used": True,
                "external_tools": sorted(set(used)),
                "warnings": warnings[:100],
            },
        }


def validate_report(report: dict[str, Any], schema_path: Path) -> None:
    try:
        import jsonschema
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        problems = list(jsonschema.Draft202012Validator(schema).iter_errors(report))
    except Exception as exc:
        raise AnalysisError("schema_validation_error", f"could not validate report: {exc}") from exc

    if problems:
        messages = []
        for p in problems[:20]:
            path = "$"
            for item in p.path:
                path += f"[{json.dumps(item)}]" if isinstance(item, str) else f"[{item}]"
            messages.append(f"{path}: {p.message}")
        raise AnalysisError("report_schema_failed", "; ".join(messages))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="file to snapshot and analyze")
    parser.add_argument(
        "--schema",
        default="/opt/jeffrey-gateway/schemas/forensics-static-report-v1.schema.json",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"maximum input size (default {DEFAULT_MAX_BYTES})",
    )
    args = parser.parse_args()

    if args.max_bytes < 1 or args.max_bytes > 1024 * 1024 * 1024:
        print(json.dumps(fail("invalid_max_bytes", "max-bytes must be between 1 and 1073741824")))
        return 2

    try:
        report = analyze(Path(args.input), args.max_bytes)
        validate_report(report, Path(args.schema))
    except AnalysisError as exc:
        print(json.dumps(fail(exc.code, exc.message), sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps(fail("internal_error", type(exc).__name__), sort_keys=True))
        return 1

    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
