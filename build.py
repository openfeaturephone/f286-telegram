"""build.py - build the Telegram app for the F286 SD-app loader: out/tg.bin.

    python build.py [--sdk ../mocor-sdk] [--tinymtproto ../tinymtproto]

Both repositories are expected next to this one (clone all three into the same folder); the
options or $MOCOR_SDK / $TINYMTPROTO point elsewhere. From the SDK it takes app_rt.h, f286_api.h,
f286_ui.h, rt.c and app.ld, wherever they sit in that tree. Needs `pip install ziglang pyelftools`.
"""
import argparse
import os
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
APP_MAGIC = 0x50414632                     # F286_APP_MAGIC: header word 0, the entry offset (8) is word 1
TG_SRCS = ["tg_sha.c", "tg_aes.c", "tg_bn.c", "tg_pq.c", "tg_tl.c", "tg_mtp.c", "tg_auth.c", "tg_net.c",
           "tg_session.c", "tg_inflate.c", "tg_tlwalk.c", "tg_schema.c", "tg_client.c"]
SDK_FILES = ["app_rt.h", "f286_api.h", "f286_ui.h", "rt.c", "app.ld"]

CFLAGS = ["-target", "thumb-freestanding-eabi", "-mcpu=cortex_a7", "-mthumb", "-Os",
          "-ffreestanding", "-fno-builtin", "-nostdlib", "-fno-stack-protector",
          "-mno-unaligned-access", "-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
          "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror",
          "-g",                            # zig strips the symbol table at -Os otherwise; -g never reaches the .bin
          "-fropi",                        # the loader copies the blob anywhere: position-independent, no RW relocations
          # zig cc ignores -mno-unaligned-access and still emits unaligned ldr.w/str.w, which fault on
          # this phone; the LLVM feature is what really turns them off
          "-Xclang", "-target-feature", "-Xclang", "+strict-align"]


def find_sdk(sdk):
    """-> {file name: path} for SDK_FILES, the shallowest match of each"""
    found = {}
    for root, dirs, files in os.walk(sdk):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for f in SDK_FILES:
            p = os.path.join(root, f)
            if f in files and (f not in found or p.count(os.sep) < found[f].count(os.sep)):
                found[f] = p
    missing = [f for f in SDK_FILES if f not in found]
    if missing:
        sys.exit(f"{sdk}: no {', '.join(missing)} (is --sdk the mocor-sdk checkout?)")
    return found


def zig(*args):
    r = subprocess.run([sys.executable, "-m", "ziglang", *args], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"FAILED: zig {' '.join(args[:1])}\n{r.stdout}{r.stderr}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", default=os.environ.get("MOCOR_SDK", os.path.join(HERE, "..", "mocor-sdk")))
    ap.add_argument("--tinymtproto", default=os.environ.get("TINYMTPROTO", os.path.join(HERE, "..", "tinymtproto")))
    a = ap.parse_args()
    sdk = find_sdk(os.path.abspath(a.sdk))
    tmt = os.path.join(os.path.abspath(a.tinymtproto), "src")
    if not os.path.exists(os.path.join(tmt, "tg_client.h")):
        sys.exit(f"{tmt}: no tg_client.h (is --tinymtproto the tinymtproto checkout?)")
    incs = sorted({os.path.dirname(sdk[f]) for f in SDK_FILES if f.endswith(".h")})

    os.makedirs(OUT, exist_ok=True)
    elf, binf = os.path.join(OUT, "tg.elf"), os.path.join(OUT, "tg.bin")
    zig("cc", *CFLAGS, "-I", os.path.join(HERE, "src"), *[x for d in incs for x in ("-I", d)], "-I", tmt,
        "-T", sdk["app.ld"], "-Wl,--gc-sections", "-Wl,-e,f286_main", "-o", elf,
        os.path.join(HERE, "src", "tg.c"), sdk["rt.c"], *[os.path.join(tmt, s) for s in TG_SRCS])
    zig("objcopy", "-O", "binary", elf, binf)

    with open(elf, "rb") as f:
        e = ELFFile(f)
        entry = None
        for s in e.get_section_by_name(".symtab").iter_symbols():
            if s.name == "f286_main":
                entry = s["st_value"] & ~1
        data = sum(s.header.sh_size for s in e.iter_sections() if s.name == ".data")
    blob = open(binf, "rb").read()
    if entry != 8 or struct.unpack_from("<II", blob) != (APP_MAGIC, 8):
        sys.exit(f"header/entry wrong (entry at {entry})")
    if data:
        sys.exit("writable data in the image")
    print(f"out/tg.bin {len(blob)} bytes")


if __name__ == "__main__":
    main()
