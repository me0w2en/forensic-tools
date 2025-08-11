#!/usr/bin/env python3

"""
[ELF Carver Utility]
This script is a forensic tool designed to locate and extract ELF binaries from disk images or raw files.
It leverages ELF program and section header structures to accurately reconstruct and carve out valid ELF files,
even from fragmented or embedded locations. Supports both 32-bit and 64-bit ELF formats, with options for minimal or full extraction.

[Usage Example]
# Carve a single ELF at a known offset (hex or decimal)
$ python elf_carver.py disk.img --offset 0x8600000

# Scan for all ELF binaries and extract each
$ python elf_carver.py disk.img --scan

# Specify output file and extraction mode
$ python elf_carver.py disk.img --offset 12345678 -o output.elf --mode minimal
"""

import argparse
import struct
from pathlib import Path

MAGIC = b"\x7fELF"

def read_at(f, off, size):
    f.seek(off)
    b = f.read(size)
    if len(b) != size:
        raise EOFError(f"Expected {size} bytes at 0x{off:X}, got {len(b)}")
    return b

def u16(b, le=True):
    return int.from_bytes(b, "little" if le else "big", signed=False)

def u32(b, le=True):
    return int.from_bytes(b, "little" if le else "big", signed=False)

def u64(b, le=True):
    return int.from_bytes(b, "little" if le else "big", signed=False)

def parse_elf_header(hdr):
    if hdr[:4] != MAGIC:
        raise ValueError("Not an ELF header (bad magic)")
    ei_class = hdr[4]
    ei_data  = hdr[5]
    le = (ei_data == 1)
    if ei_class == 1:
        e_phoff      = u32(hdr[0x1C:0x20], le)
        e_shoff      = u32(hdr[0x20:0x24], le)
        e_ehsize     = u16(hdr[0x34:0x36], le)
        e_phentsize  = u16(hdr[0x2A:0x2C], le)
        e_phnum      = u16(hdr[0x2C:0x2E], le)
        e_shentsize  = u16(hdr[0x2E:0x30], le)
        e_shnum      = u16(hdr[0x30:0x32], le)
    elif ei_class == 2:
        e_phoff      = u64(hdr[0x20:0x28], le)
        e_shoff      = u64(hdr[0x28:0x30], le)
        e_ehsize     = u16(hdr[0x34:0x36], le)
        e_phentsize  = u16(hdr[0x36:0x38], le)
        e_phnum      = u16(hdr[0x38:0x3A], le)
        e_shentsize  = u16(hdr[0x3A:0x3C], le)
        e_shnum      = u16(hdr[0x3C:0x3E], le)
    else:
        raise ValueError(f"Unknown EI_CLASS={ei_class}")
    return {
        "class": ei_class,
        "little_endian": le,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_ehsize": e_ehsize,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
    }

def parse_ph_entry(entry_bytes, elf_class, le):
    if elf_class == 1:
        p_type   = u32(entry_bytes[0x00:0x04], le)
        p_offset = u32(entry_bytes[0x04:0x08], le)
        p_filesz = u32(entry_bytes[0x10:0x14], le)
    else:
        p_type   = u32(entry_bytes[0x00:0x04], le)
        p_flags  = u32(entry_bytes[0x04:0x08], le)
        p_offset = u64(entry_bytes[0x08:0x10], le)
        p_filesz = u64(entry_bytes[0x20:0x28], le)
    return p_type, p_offset, p_filesz

def parse_sh_entry(entry_bytes, elf_class, le):
    if elf_class == 1:
        sh_type   = u32(entry_bytes[0x04:0x08], le)
        sh_offset = u32(entry_bytes[0x10:0x14], le)
        sh_size   = u32(entry_bytes[0x14:0x18], le)
    else:
        sh_type   = u32(entry_bytes[0x04:0x08], le)
        sh_offset = u64(entry_bytes[0x18:0x20], le)
        sh_size   = u64(entry_bytes[0x20:0x28], le)
    return sh_type, sh_offset, sh_size

SHT_NOBITS = 8

def compute_bounds(f, base_off, hdr):
    le = hdr["little_endian"]
    elf_class = hdr["class"]
    max_p_end = 0
    ph_start = base_off + hdr["e_phoff"]
    for i in range(hdr["e_phnum"]):
        ent_off = ph_start + i*hdr["e_phentsize"]
        ent = read_at(f, ent_off, hdr["e_phentsize"])
        p_type, p_offset, p_filesz = parse_ph_entry(ent, elf_class, le)
        if p_filesz == 0:
            continue
        end = p_offset + p_filesz
        if end > max_p_end:
            max_p_end = end
    ph_table_end = hdr["e_phoff"] + hdr["e_phnum"]*hdr["e_phentsize"] if hdr["e_phnum"] > 0 else 0
    max_s_end = 0
    sh_start = base_off + hdr["e_shoff"] if hdr["e_shnum"] > 0 else 0
    for j in range(hdr["e_shnum"]):
        ent_off = sh_start + j*hdr["e_shentsize"]
        ent = read_at(f, ent_off, hdr["e_shentsize"])
        sh_type, sh_offset, sh_size = parse_sh_entry(ent, elf_class, le)
        if sh_type == SHT_NOBITS:
            continue
        if sh_size == 0:
            continue
        end = sh_offset + sh_size
        if end > max_s_end:
            max_s_end = end
    sh_table_end = hdr["e_shoff"] + hdr["e_shnum"]*hdr["e_shentsize"] if hdr["e_shnum"] > 0 else 0
    return max_p_end, max_s_end, ph_table_end, sh_table_end

def align_up(x, a):
    if a <= 1:
        return x
    return ((x + a - 1) // a) * a

def carve(image_path, out_path, start_off, mode="full", align=4096, verbose=False):
    with open(image_path, "rb") as f:
        elf_hdr = read_at(f, start_off, 64)
        hdr = parse_elf_header(elf_hdr)
        if verbose:
            print(f"[+] EI_CLASS: {'ELF64' if hdr['class']==2 else 'ELF32'}, "
                  f"Endian: {'LE' if hdr['little_endian'] else 'BE'}")
            print(f"[+] e_phoff=0x{hdr['e_phoff']:X}, e_phentsize={hdr['e_phentsize']}, e_phnum={hdr['e_phnum']}")
            print(f"[+] e_shoff=0x{hdr['e_shoff']:X}, e_shentsize={hdr['e_shentsize']}, e_shnum={hdr['e_shnum']}")
        max_p_end, max_s_end, ph_table_end, sh_table_end = compute_bounds(f, start_off, hdr)
        if verbose:
            print(f"[+] MAX_P (p_offset+p_filesz): 0x{max_p_end:X}")
            print(f"[+] MAX_S (sh_offset+sh_size, excl. NOBITS): 0x{max_s_end:X}")
            print(f"[+] PH table end: 0x{ph_table_end:X}")
            print(f"[+] SH table end: 0x{sh_table_end:X}")
        if mode == "minimal":
            end_candidate = max(max_p_end, ph_table_end)
        else:
            end_candidate = max(max_p_end, max_s_end, ph_table_end, sh_table_end)
        count = align_up(end_candidate, align)
        if verbose:
            print(f"[+] Chosen end candidate: 0x{end_candidate:X}")
            print(f"[+] Aligned count ({align}): 0x{count:X} ({count} bytes)")
        f.seek(start_off)
        data = f.read(count)
        with open(out_path, "wb") as out:
            out.write(data)
        return {
            "hdr": hdr,
            "MAX_P": max_p_end,
            "MAX_S": max_s_end,
            "PH_table_end": ph_table_end,
            "SH_table_end": sh_table_end,
            "end_candidate": end_candidate,
            "count": count,
        }

def find_all_magic(image_path, limit=None):
    res = []
    chunk = 1024 * 1024
    with open(image_path, "rb") as f:
        pos = 0
        prev = b""
        while True:
            data = f.read(chunk)
            if not data: break
            buf = prev + data
            i = 0
            while True:
                j = buf.find(MAGIC, i)
                if j == -1:
                    break
                off = pos - len(prev) + j
                res.append(off)
                if limit and len(res) >= limit:
                    return res
                i = j + 1
            pos += len(data)
            prev = buf[-3:]
    return res

def main():
    ap = argparse.ArgumentParser(description="ELF carver (PH/SH-aware)")
    ap.add_argument("image", help="disk image / raw file")
    ap.add_argument("-o", "--out", help="output file (default: <offset>.elf)")
    ap.add_argument("--offset", help="ELF start offset (e.g., 0x8600000 or 140509184)")
    ap.add_argument("--scan", action="store_true", help="scan for all ELF magics and carve each")
    ap.add_argument("--mode", choices=["minimal","full"], default="full", help="carving mode (default: full)")
    ap.add_argument("--align", type=int, default=4096, help="alignment (bytes) for count")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--limit", type=int, default=None, help="limit number of magics when scanning")
    args = ap.parse_args()
    img = Path(args.image)
    if not img.exists():
        raise SystemExit(f"Image not found: {img}")
    if args.scan:
        offs = find_all_magic(str(img), limit=args.limit)
        if not offs:
            raise SystemExit("No ELF magic found")
        for k, off in enumerate(offs):
            out = args.out or f"{img.stem}_off_{off:#x}.elf"
            if args.out and args.limit != 1:
                out = f"{Path(args.out).stem}_{k}{Path(args.out).suffix or '.elf'}"
            info = carve(str(img), out, off, mode=args.mode, align=args.align, verbose=args.verbose)
            if args.verbose:
                print(f"[+] Wrote {out}")
        return
    if not args.offset:
        raise SystemExit("Provide --offset (or use --scan)")
    off_str = args.offset.lower()
    start_off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
    out = args.out or f"{img.stem}_off_{start_off:#x}.elf"
    info = carve(str(img), out, start_off, mode=args.mode, align=args.align, verbose=args.verbose)
    if args.verbose:
        print(f"[+] Wrote {out}")

if __name__ == "__main__":
    main()
