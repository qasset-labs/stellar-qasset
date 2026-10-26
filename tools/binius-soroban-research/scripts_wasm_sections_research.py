#!/usr/bin/env python3
"""Dependency-free WASM module section-size breakdown (no wasm-objdump/twiggy needed).
Research-only: reads an existing compiled .wasm fixture and reports section sizes,
to compare where code-size differs between two already-built artifacts.
"""
import sys

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount", 13: "tag",
}


def read_uleb128(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos


def analyze(path):
    with open(path, "rb") as f:
        buf = f.read()
    assert buf[0:4] == b"\x00asm", f"not a wasm module: {path}"
    pos = 8
    sections = {}
    custom_sections = {}
    while pos < len(buf):
        sec_id = buf[pos]
        pos += 1
        size, pos = read_uleb128(buf, pos)
        content_start = pos
        name = SECTION_NAMES.get(sec_id, f"unknown[{sec_id}]")
        sections[name] = sections.get(name, 0) + size
        if sec_id == 0:
            name_len, name_pos = read_uleb128(buf, content_start)
            custom_name = buf[name_pos:name_pos + name_len].decode("utf-8", "replace")
            custom_sections[custom_name] = custom_sections.get(custom_name, 0) + size
        pos = content_start + size
    return len(buf), sections, custom_sections


def main():
    paths = sys.argv[1:]
    results = {p: analyze(p) for p in paths}
    all_names = sorted(set(n for _, secs, _ in results.values() for n in secs))
    print(f"{'section':<12}", end="")
    for p in paths:
        print(f"{p.split('/')[-1]:>28}", end="")
    print()
    for name in all_names:
        print(f"{name:<12}", end="")
        for p in paths:
            total, secs, _ = results[p]
            print(f"{secs.get(name, 0):>28,}", end="")
        print()
    print(f"{'TOTAL':<12}", end="")
    for p in paths:
        total, secs, _ = results[p]
        print(f"{total:>28,}", end="")
    print()
    print()
    for p in paths:
        total, secs, customs = results[p]
        if customs:
            print(f"custom sections in {p}:")
            for n, s in sorted(customs.items(), key=lambda kv: -kv[1]):
                print(f"  {n:<30} {s:>10,} bytes")


if __name__ == "__main__":
    main()
