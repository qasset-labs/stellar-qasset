#!/usr/bin/env python3
"""Lossless canonical integer recoding of the exact immutable research preprocessing."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

OLD_SHA = '4d6fd19ea0092a261ed7041985b679ecad4b45f9cc6452a7a717979be7c35ef3'
NEW_SHA = '0d1a3b775ce006e07df6af3aa1491d2d7c29202e11985fd6045ef398cb3be424'
OLD_BYTES, NEW_BYTES = 2714051, 1286664
OLD_MAGIC = b'qasset-fixed-binius-zk-preprocessing-v1\0'
NEW_MAGIC = b'qasset-fixed-binius-zk-preprocessing-v2\0'
PIN = b'115108d5a661d95c0b474b6ab02558bfe6c6bec7'
PROGRAM = b'qasset-binius-leaf-clamp-research-v1'

class Reader:
    def __init__(self, data): self.data, self.at = data, 0
    def read(self, count):
        result = self.data[self.at:self.at+count]
        if len(result) != count: raise ValueError('truncated preprocessing')
        self.at += count
        return result
    def u32(self): return struct.unpack('<I', self.read(4))[0]
    def var(self):
        value = 0
        for i in range(5):
            byte = self.read(1)[0]
            if i == 4 and byte > 15: raise ValueError('integer overflow')
            value |= (byte & 127) << (7*i)
            if not byte & 128:
                if i and not byte: raise ValueError('nonminimal integer')
                return value
        raise ValueError('overlong integer')

def var(value):
    if not 0 <= value <= 0xffffffff: raise ValueError('integer range')
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return output

def recode(data, compact):
    source_magic, destination_magic = (OLD_MAGIC, NEW_MAGIC) if compact else (NEW_MAGIC, OLD_MAGIC)
    r = Reader(data)
    if r.read(len(source_magic)) != source_magic or r.read(40) != PIN or r.read(len(PROGRAM)) != PROGRAM:
        raise ValueError('fixed source identity')
    r.read(32 + 8) # Exact source fingerprint, configured security bits and inverse-rate exponent.
    r.read(r.u32()) # Upstream serialized inner constraint system remains byte-for-byte unchanged.
    r.read(4) # Public-word dimension.
    r.read(16 * r.u32()) # Outer constants.
    r.read(5 * 4) # Outer dimensions and constant-one index.
    count = r.u32()
    if count != 82373: raise ValueError('fixed constraint count')
    output = bytearray(data[:r.at])
    output[:len(source_magic)] = destination_magic
    for _ in range(count * 3):
        length = r.u32() if compact else r.var()
        if length > 65536: raise ValueError('operand bound')
        output.extend(var(length) if compact else struct.pack('<I', length))
        for _ in range(length):
            if compact:
                tag, index = r.read(1)[0], r.u32()
                if tag > 2: raise ValueError('wire tag')
                output.extend(var(index * 4 + tag))
            else:
                packed = r.var()
                tag, index = packed & 3, packed >> 2
                if tag > 2: raise ValueError('wire tag')
                output.extend(bytes([tag]) + struct.pack('<I', index))
    output.extend(data[r.at:]) # Blinding, oracle and complete FRI parameters remain identical.
    return bytes(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.original.stat().st_size != OLD_BYTES: raise ValueError('original byte bound')
    with args.original.open('rb') as handle: original = handle.read(OLD_BYTES + 1)
    if hashlib.sha256(original).hexdigest() != OLD_SHA: raise ValueError('original immutable hash')
    encoded = recode(original, True)
    if len(encoded) != NEW_BYTES or hashlib.sha256(encoded).hexdigest() != NEW_SHA:
        raise ValueError('compact immutable hash')
    expanded = recode(encoded, False)
    if expanded != original: raise ValueError('lossless roundtrip')
    args.output.write_bytes(encoded)
    print(json.dumps({'status': 'passed_exact_lossless_preprocessing_recoding_only',
                      'original_bytes': len(original), 'compact_bytes': len(encoded),
                      'original_sha256': OLD_SHA, 'compact_sha256': NEW_SHA,
                      'byte_exact_expansion_equal': True, 'security_approved': False}))

if __name__ == '__main__': main()
