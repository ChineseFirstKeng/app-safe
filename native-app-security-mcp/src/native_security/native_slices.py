"""Bounded carrier/slice headers; no symbol or language recovery is claimed here."""
import hashlib
import struct

from .errors import AnalysisError

THIN = {b"\xcf\xfa\xed\xfe": ("<", 32), b"\xce\xfa\xed\xfe": ("<", 28),
        b"\xfe\xed\xfa\xcf": (">", 32), b"\xfe\xed\xfa\xce": (">", 28)}
FAT = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
       b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}


def thin(data, offset=0):
    layout = THIN.get(data[:4])
    if layout is None:
        raise AnalysisError("unsupported_native_format")
    endian, header_size = layout
    if len(data) < header_size:
        raise AnalysisError("truncated_macho_header")
    cpu, subtype, _, count, length, _ = struct.unpack_from(endian + "6I", data, 4)
    if count > 4096 or header_size + length > len(data):
        raise AnalysisError("invalid_macho_commands")
    cursor, encrypted = header_size, False
    for _ in range(count):
        if cursor + 8 > header_size + length:
            raise AnalysisError("invalid_macho_commands")
        command, size = struct.unpack_from(endian + "II", data, cursor)
        if size < 8 or cursor + size > header_size + length:
            raise AnalysisError("invalid_macho_commands")
        if command in {0x21, 0x2c}:
            if size < (24 if command == 0x2c else 20):
                raise AnalysisError("invalid_macho_encryption_command")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, cursor + 8)
            if cryptoff + cryptsize > len(data):
                raise AnalysisError("invalid_macho_encryption_range")
            encrypted |= cryptid != 0
        cursor += size
    if cursor != header_size + length:
        raise AnalysisError("invalid_macho_commands")
    return {"format": "macho", "offset": offset, "size": len(data), "cpu": cpu, "cpu_subtype": subtype,
            "architecture": {12: "arm", 0x100000c: "arm64", 7: "x86", 0x1000007: "x86_64"}.get(cpu, "unsupported"),
            "architecture_variant": "arm64e" if cpu == 0x100000c and subtype & 0xffffff == 2 else None,
            "encrypted": encrypted, "sha256": hashlib.sha256(data).hexdigest()}


def slices(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise AnalysisError("invalid_native_input")
    if not isinstance(data, bytes):
        data = bytes(data)
    if len(data) < 8:
        raise AnalysisError("truncated_native_header")
    if data.startswith(b"\x7fELF"):
        if data[4] not in {1, 2} or data[5] not in {1, 2} or len(data) < (52 if data[4] == 1 else 64):
            raise AnalysisError("invalid_elf_header")
        cpu = struct.unpack_from(("<" if data[5] == 1 else ">") + "H", data, 18)[0]
        return [{"format": "elf", "offset": 0, "size": len(data), "cpu": cpu, "encrypted": False,
                 "architecture": {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64"}.get(cpu, "unsupported"),
                 "sha256": hashlib.sha256(data).hexdigest()}]
    if data[:4] not in FAT:
        return [thin(data)]
    endian, stride = FAT[data[:4]]
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if not 1 <= count <= 16 or 8 + count * stride > len(data):
        raise AnalysisError("invalid_fat_header")
    result, intervals = [], []
    for i in range(count):
        base = 8 + i * stride
        cpu, subtype = struct.unpack_from(endian + "II", data, base)
        offset, size = struct.unpack_from(endian + ("QQ" if stride == 32 else "II"), data, base + 8)
        if not size or offset < 8 + count * stride or offset + size > len(data):
            raise AnalysisError("invalid_fat_slice_range")
        if any(offset < stop and start < offset + size for start, stop in intervals):
            raise AnalysisError("overlapping_fat_slices")
        intervals.append((offset, offset + size))
        item = thin(data[offset:offset + size], offset)
        if item["cpu"] != cpu:
            raise AnalysisError("fat_cpu_mismatch")
        if item["cpu_subtype"] != subtype:
            raise AnalysisError("fat_cpu_subtype_mismatch")
        result.append(item)
    return result
