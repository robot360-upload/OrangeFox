#!/usr/bin/env python3
"""Inspect Android boot v0-v2 images, safely extract gzip/newc ramdisks,
parse recovery DTBO tables, and extract concatenated FDTs.

Uses only the Python standard library. Intended for known Android images; it
never executes content from an image and never follows archive symlinks while
extracting files.
"""
from __future__ import annotations
import gzip
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path, PurePosixPath

PAGE = 4096
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
DT_TABLE_MAGIC = 0xD7B7AB1E
AVB_MAGIC = b"AVB0"


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def align(value: int, page: int) -> int:
    return (value + page - 1) // page * page


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relpath(name: str) -> Path | None:
    # Android newc archives should use relative POSIX paths. Reject absolute,
    # empty, parent-traversal, and NUL-containing paths.
    if not name or "\x00" in name or name.startswith("/"):
        return None
    p = PurePosixPath(name)
    if any(part in ("..", "") for part in p.parts):
        return None
    return Path(*p.parts)


def parse_newc(blob: bytes, dest: Path) -> dict:
    """Extract newc/crc cpio entries without invoking cpio or following links."""
    pos = 0
    entries = []
    skipped = []
    total = len(blob)
    while pos + 110 <= total:
        magic = blob[pos:pos + 6]
        if magic not in (b"070701", b"070702"):
            raise ValueError(f"Invalid cpio magic at offset 0x{pos:x}: {magic!r}")
        fields = []
        for i in range(13):
            raw = blob[pos + 6 + i * 8: pos + 14 + i * 8]
            try:
                fields.append(int(raw, 16))
            except ValueError as exc:
                raise ValueError(f"Invalid cpio field at 0x{pos:x}") from exc
        (ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
         rdevmajor, rdevminor, namesize, check) = fields
        name_start = pos + 110
        name_end = name_start + namesize
        if namesize < 1 or name_end > total:
            raise ValueError(f"Invalid cpio filename length at 0x{pos:x}")
        name_bytes = blob[name_start:name_end]
        if not name_bytes.endswith(b"\0"):
            raise ValueError(f"Unterminated cpio filename at 0x{pos:x}")
        name = name_bytes[:-1].decode("utf-8", "surrogateescape")
        data_start = align(name_end, 4)
        data_end = data_start + filesize
        if data_end > total:
            raise ValueError(f"Truncated cpio data for {name!r}")
        payload = blob[data_start:data_end]
        pos = align(data_end, 4)
        if name == "TRAILER!!!":
            break
        rel = safe_relpath(name)
        if rel is None:
            skipped.append({"name": name, "reason": "unsafe path"})
            continue
        # Limit extraction to regular files, directories, and symlinks.
        kind = mode & 0o170000
        if kind not in (0o100000, 0o040000, 0o120000):
            skipped.append({"name": name, "reason": f"unsupported mode {oct(mode)}"})
            continue
        entries.append((rel, name, mode, payload, kind))

    dest.mkdir(parents=True, exist_ok=True)
    # Create all directories and regular files first. This avoids writing
    # through symlinks supplied by the archive.
    for rel, name, mode, payload, kind in entries:
        target = dest / rel
        if kind == 0o120000:
            continue
        if kind == 0o040000:
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            try:
                target.chmod(mode & 0o777)
            except OSError:
                pass
    symlinks = 0
    # Create deeper symlinks first. If an archive contains a symlink-only
    # parent path, creating its child first forces a real directory to exist;
    # the parent symlink is then skipped rather than redirecting extraction.
    symlink_entries = sorted(
        (entry for entry in entries if entry[4] == 0o120000),
        key=lambda entry: len(entry[0].parts), reverse=True)
    for rel, name, mode, payload, kind in symlink_entries:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            link_target = payload.decode("utf-8", "surrogateescape")
            if target.exists() or target.is_symlink():
                if target.is_dir() and not target.is_symlink():
                    continue
                target.unlink()
            target.symlink_to(link_target)
            symlinks += 1
        except (OSError, ValueError):
            skipped.append({"name": name, "reason": "symlink creation failed"})
    return {"entry_count": len(entries), "symlink_count": symlinks,
            "skipped": skipped, "cpio_bytes": total}


def parse_fdt_bundle(data: bytes, start: int, length: int, outdir: Path, prefix: str) -> list[dict]:
    """Parse concatenated DTBs within a known bounded section."""
    end = min(len(data), start + length)
    found = []
    pos = start
    index = 0
    # Ignore padding before the first FDT, but after the first DTB require
    # contiguous blobs (as used by this kernel's appended DTB bundle).
    first = True
    while pos + 8 <= end:
        if data[pos:pos + 4] != FDT_MAGIC:
            if first:
                next_pos = data.find(FDT_MAGIC, pos, end)
                if next_pos < 0:
                    break
                pos = next_pos
            else:
                break
        if pos + 40 > end:
            break
        totalsize = struct.unpack_from(">I", data, pos + 4)[0]
        if totalsize < 40 or pos + totalsize > end:
            # The section may contain trailing alignment bytes; stop rather
            # than scanning arbitrary data and misclassifying overlays.
            break
        blob = data[pos:pos + totalsize]
        out = outdir / f"{prefix}-dtb-{index:03d}.dtb"
        out.write_bytes(blob)
        found.append({"index": index, "offset": pos, "offset_hex": hex(pos),
                      "size": totalsize, "file": out.name,
                      "sha256": sha256(blob)})
        pos += totalsize
        index += 1
        first = False
    return found


def parse_dtbo_table(data: bytes, offset: int, size: int, outdir: Path, prefix: str) -> dict:
    if offset < 0 or size < 32 or offset + size > len(data):
        return {"present": False, "error": "DTBO section bounds invalid"}
    if data[offset:offset + 4] != struct.pack(">I", DT_TABLE_MAGIC):
        return {"present": False, "error": "DT table magic not found at header offset"}
    (magic, total_size, header_size, entry_size, count, entries_offset,
     page_size, version) = struct.unpack_from(">8I", data, offset)
    table_end = offset + min(total_size, size)
    if header_size < 32 or entry_size < 32 or count > 4096:
        return {"present": True, "error": "Implausible DT table header",
                "total_size": total_size, "header_size": header_size,
                "entry_size": entry_size, "entry_count": count}
    entries = []
    for i in range(count):
        eoff = offset + entries_offset + i * entry_size
        if eoff + 32 > table_end:
            entries.append({"index": i, "error": "entry outside table bounds"})
            break
        fields = struct.unpack_from(">8I", data, eoff)
        dt_size, dt_offset, dt_id, rev, c0, c1, c2, c3 = fields
        abs_offset = offset + dt_offset
        item = {"index": i, "dt_size": dt_size, "dt_offset": dt_offset,
                "absolute_offset": abs_offset, "absolute_offset_hex": hex(abs_offset),
                "id": dt_id, "rev": rev, "custom": [c0, c1, c2, c3]}
        if dt_size > 0 and abs_offset >= offset and abs_offset + dt_size <= table_end:
            blob = data[abs_offset:abs_offset + dt_size]
            out = outdir / f"{prefix}-dtbo-{i:03d}.dtbo"
            out.write_bytes(blob)
            item.update({"file": out.name, "sha256": sha256(blob),
                         "starts_with_fdt_magic": blob.startswith(FDT_MAGIC)})
        else:
            item["error"] = "overlay payload outside DTBO table bounds"
        entries.append(item)
    return {"present": True, "magic": hex(magic), "offset": offset,
            "offset_hex": hex(offset), "declared_size": size,
            "total_size": total_size, "header_size": header_size,
            "entry_size": entry_size, "entry_count": count,
            "entries_offset": entries_offset, "page_size": page_size,
            "version": version, "entries": entries}


def inspect_image(path: Path, root: Path) -> dict:
    data = path.read_bytes()
    name = path.stem
    result = {"filename": path.name, "size_bytes": len(data), "sha256": sha256(data)}
    if not data.startswith(b"ANDROID!"):
        result["error"] = "Not an Android boot image with ANDROID! magic"
        return result
    if len(data) < 1660:
        result["error"] = "Image too short for boot header v2"
        return result
    kernel_size, kernel_addr = u32(data, 8), u32(data, 12)
    ramdisk_size, ramdisk_addr = u32(data, 16), u32(data, 20)
    second_size, second_addr = u32(data, 24), u32(data, 28)
    tags_addr, page_size, version = u32(data, 32), u32(data, 36), u32(data, 40)
    board = data[48:64].split(b"\0", 1)[0].decode("ascii", "replace")
    header = {"header_version": version, "kernel_size": kernel_size,
              "kernel_addr": hex(kernel_addr), "ramdisk_size": ramdisk_size,
              "ramdisk_addr": hex(ramdisk_addr), "second_size": second_size,
              "second_addr": hex(second_addr), "tags_addr": hex(tags_addr),
              "page_size": page_size, "board": board}
    result["header"] = header
    if version < 0 or version > 2 or page_size == 0:
        result["error"] = "This extractor supports Android boot header versions 0-2 only"
        return result
    header_size = u32(data, 1644) if version >= 1 else None
    recovery_dtbo_size = u32(data, 1632) if version >= 1 else 0
    recovery_dtbo_offset = u64(data, 1636) if version >= 1 else 0
    dtb_size = u32(data, 1648) if version >= 2 else 0
    dtb_addr = u64(data, 1652) if version >= 2 else 0
    result["header_extension"] = {"header_size": header_size,
        "recovery_dtbo_size": recovery_dtbo_size,
        "recovery_dtbo_offset": hex(recovery_dtbo_offset),
        "dtb_size": dtb_size, "dtb_addr": hex(dtb_addr)}
    kernel_off = page_size
    ramdisk_off = kernel_off + align(kernel_size, page_size)
    second_off = ramdisk_off + align(ramdisk_size, page_size)
    result["payloads"] = {"kernel_offset": kernel_off, "kernel_offset_hex": hex(kernel_off),
        "ramdisk_offset": ramdisk_off, "ramdisk_offset_hex": hex(ramdisk_off),
        "second_offset": second_off, "second_offset_hex": hex(second_off)}
    if kernel_off + kernel_size > len(data) or ramdisk_off + ramdisk_size > len(data):
        result["error"] = "Kernel or ramdisk payload exceeds image bounds"
        return result
    kernel = data[kernel_off:kernel_off + kernel_size]
    kernel_out = root / "kernel"
    kernel_out.mkdir(parents=True, exist_ok=True)
    (kernel_out / f"{name}-kernel.gz").write_bytes(kernel)
    result["kernel"] = {"size": len(kernel), "sha256": sha256(kernel),
        "gzip_magic": kernel.startswith(b"\x1f\x8b"),
        "file": f"kernel/{name}-kernel.gz"}
    try:
        uncompressed = gzip.decompress(kernel)
        result["kernel"]["gzip_decompress_ok"] = True
        result["kernel"]["uncompressed_size"] = len(uncompressed)
        result["kernel"]["uncompressed_sha256"] = sha256(uncompressed)
        result["kernel"]["arm64_image_magic"] = (
            len(uncompressed) >= 0x3c and uncompressed[0x38:0x3c] == b"ARM\x64")
    except (OSError, EOFError) as exc:
        result["kernel"]["gzip_decompress_ok"] = False
        result["kernel"]["gzip_error"] = str(exc)
    ramdisk_blob = data[ramdisk_off:ramdisk_off + ramdisk_size]
    ramdisk_dir = root / "ramdisk" / name
    ramdisk_dir.mkdir(parents=True, exist_ok=True)
    ramdisk_gz = root / "ramdisk" / f"{name}-ramdisk.gz"
    ramdisk_gz.write_bytes(ramdisk_blob)
    try:
        cpio_blob = gzip.decompress(ramdisk_blob)
        cpio_path = root / "ramdisk" / f"{name}-ramdisk.cpio"
        cpio_path.write_bytes(cpio_blob)
        result["ramdisk"] = {"compression": "gzip", "compressed_size": len(ramdisk_blob),
            "uncompressed_size": len(cpio_blob), "cpio_file": str(cpio_path.relative_to(root))}
        result["ramdisk"].update(parse_newc(cpio_blob, ramdisk_dir))
        result["ramdisk"]["extracted_dir"] = str(ramdisk_dir.relative_to(root))
    except (OSError, EOFError, ValueError) as exc:
        result["ramdisk"] = {"compressed_size": len(ramdisk_blob), "error": str(exc)}
    # v1/v2 recovery DTBO is embedded at the offset recorded in the header.
    if version >= 1 and recovery_dtbo_size:
        dtbo = parse_dtbo_table(data, recovery_dtbo_offset, recovery_dtbo_size,
                                root / "dtbo", name)
        result["recovery_dtbo"] = dtbo
        dtb_start_min = recovery_dtbo_offset + align(recovery_dtbo_size, page_size)
    else:
        result["recovery_dtbo"] = {"present": False}
        dtb_start_min = second_off + align(second_size, page_size)
    if version >= 2 and dtb_size:
        # Some mkbootimg versions place a zero-filled page between recovery_dtbo
        # and DTB; search from the calculated minimum to the first valid FDT.
        dtb_start = data.find(FDT_MAGIC, dtb_start_min,
                              min(len(data), dtb_start_min + page_size * 2))
        if dtb_start < 0:
            result["dtb_bundle"] = {"error": "No FDT found near calculated DTB start",
                                    "minimum_offset": hex(dtb_start_min), "size": dtb_size}
        else:
            blobs = parse_fdt_bundle(data, dtb_start, dtb_size, root / "dtb", name)
            result["dtb_bundle"] = {"offset": dtb_start, "offset_hex": hex(dtb_start),
                "declared_size": dtb_size, "load_address": hex(dtb_addr),
                "entries_found": len(blobs), "entries": blobs}
    else:
        result["dtb_bundle"] = {"present": False}
    avb_positions = [m.start() for m in re.finditer(re.escape(AVB_MAGIC), data)]
    result["avb_magic_offsets"] = [hex(p) for p in avb_positions]
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} IMAGE_DIR OUTPUT_DIR", file=sys.stderr)
        return 2
    image_dir, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for d in (out / "kernel", out / "ramdisk", out / "dtb", out / "dtbo", out / "metadata"):
        d.mkdir(parents=True, exist_ok=True)
    results = {}
    for filename in ("boot.img", "recovery.img"):
        path = image_dir / filename
        if not path.is_file():
            results[filename] = {"error": f"Missing input image: {path}"}
            continue
        try:
            results[filename] = inspect_image(path, out)
        except Exception as exc:
            results[filename] = {"error": f"Inspection exception: {type(exc).__name__}: {exc}"}
    report = out / "metadata" / "image-analysis.json"
    report.write_text(json.dumps(results, indent=2))
    # Human-readable summary plus extracted configuration files.
    lines = ["gta4l Android image inspection", "==============================", ""]
    for filename, item in results.items():
        lines += [f"## {filename}"]
        if "error" in item:
            lines += [f"ERROR: {item['error']}", ""]
            continue
        h = item.get("header", {})
        e = item.get("header_extension", {})
        lines += [f"Size: {item['size_bytes']} bytes",
                  f"SHA-256: {item['sha256']}",
                  f"Header: v{h.get('header_version')} / page {h.get('page_size')}",
                  f"Board: {h.get('board')}",
                  f"Kernel: offset {item['payloads']['kernel_offset_hex']}, size {h.get('kernel_size')}, gzip={item.get('kernel',{}).get('gzip_decompress_ok')}",
                  f"Ramdisk: offset {item['payloads']['ramdisk_offset_hex']}, size {h.get('ramdisk_size')}, extracted={item.get('ramdisk',{}).get('entry_count', 0)} entries",
                  f"Recovery DTBO: offset {e.get('recovery_dtbo_offset')}, size {e.get('recovery_dtbo_size')}, entries={item.get('recovery_dtbo',{}).get('entry_count', 0)}",
                  f"DTB: offset {item.get('dtb_bundle',{}).get('offset_hex')}, size {e.get('dtb_size')}, blobs={item.get('dtb_bundle',{}).get('entries_found', 0)}",
                  ""]
    (out / "metadata" / "summary.txt").write_text("\n".join(lines))
    # Copy the device fstab and init files as explicit convenient outputs.
    config_report = out / "metadata" / "recovery-config-files.txt"
    patterns = ("recovery.fstab", "fstab.emmc", "fstab.default", "init.rc", "init.qcom.recovery.rc", "prop.default")
    with config_report.open("w") as f:
        for root in (out / "ramdisk").glob("*/"):
            for p in root.rglob("*"):
                if p.is_file() and (p.name in patterns or "fstab" in p.name.lower()):
                    try:
                        text = p.read_text(errors="replace")
                    except OSError:
                        continue
                    f.write(f"\n===== {p.relative_to(out)} =====\n{text}\n")
    print((out / "metadata" / "summary.txt").read_text())
    print(f"Detailed JSON: {report}")
    # Fail loudly if any expected payload wasn't actually extracted. This keeps
    # a workflow run from appearing green just because an optional tool was absent.
    valid = True
    for filename, item in results.items():
        if "error" in item:
            valid = False
            continue
        if not item.get("ramdisk", {}).get("entry_count", 0):
            print(f"ERROR: {filename}: ramdisk extraction produced no entries", file=sys.stderr)
            valid = False
        if item.get("header", {}).get("header_version", 0) >= 2:
            if item.get("header_extension", {}).get("dtb_size", 0) and not item.get("dtb_bundle", {}).get("entries_found", 0):
                print(f"ERROR: {filename}: DTB bundle declared but no FDTs parsed", file=sys.stderr)
                valid = False
        dtbo = item.get("recovery_dtbo", {})
        if dtbo.get("present") and ("error" in dtbo or len(dtbo.get("entries", [])) != dtbo.get("entry_count")):
            print(f"ERROR: {filename}: DTBO table could not be parsed completely", file=sys.stderr)
            valid = False
    return 0 if valid else 1

if __name__ == "__main__":
    sys.exit(main())
