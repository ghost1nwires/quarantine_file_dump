#!/usr/bin/env python3
r"""
Carve original files out of a Windows Defender quarantine folder.

Self-contained: point it at the folder that DIRECTLY contains
Entries\ and ResourceData\  (e.g. C:\Quarantine), not a disk root.

Usage:
    python carve.py C:\Quarantine                  # list file-type entries
    python carve.py C:\Quarantine --dump           # carve -> quarantine.tar
    python carve.py C:\Quarantine --dump -o out.tar
"""
import io
import struct
import hashlib
import argparse
import pathlib
import tarfile

# Hardcoded RC4 key obtained from mpengine.dll
KEY = [
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
    0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
    0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
    0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
    0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
    0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
    0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
    0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
    0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
    0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
    0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
    0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
    0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
    0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
    0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
    0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
    0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
    0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
    0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
    0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
    0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
    0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
    0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
]


def mse_ksa():
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + KEY[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def rc4_decrypt(data):
    sbox = mse_ksa()
    out = bytearray(len(data))
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out[k] = sbox[(sbox[i] + sbox[j]) % 256] ^ data[k]
    return out


def unpack_malware(f):
    decrypted = rc4_decrypt(f.read())
    sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
    header_len = 0x28 + sd_len
    malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
    return decrypted[header_len:header_len + malfile_len], malfile_len


def get_entry(data):
    pos = data.find(b'\x00\x00\x00') + 1
    path_str = data[:pos].decode('utf-16le')
    if path_str[2:4] == '?\\':
        path_str = path_str[4:]
    path = pathlib.PureWindowsPath(path_str)
    pos += 4                                   # skip entry-count field
    type_len = data[pos:].find(b'\x00')
    typ = data[pos:pos + type_len].decode()    # entry type (UTF-8)
    pos += type_len + 1
    pos += (4 - pos) % 4                        # align
    pos += 4                                    # skip metadata
    h = data[pos:pos + 20].hex().upper()
    return path, h, typ


def parse_entries(base):
    results = []
    for guid in sorted(base.glob('Entries/{*}')):
        with open(guid, 'rb') as f:
            header = rc4_decrypt(f.read(0x3c))
            d1_len, d2_len = struct.unpack_from('<II', header, 0x28)
            f.read(d1_len)                                  # skip data1 (timestamp/detection)
            data2 = rc4_decrypt(f.read(d2_len))
            cnt = struct.unpack_from('<I', data2)[0]
            offsets = struct.unpack_from('<' + str(cnt) + 'I', data2, 0x4)
            for o in offsets:
                path, h, typ = get_entry(data2[o:])
                if typ == 'file' and h:
                    results.append((path, h))
    return results


def main():
    ap = argparse.ArgumentParser(
        description='Carve original files from a Windows Defender quarantine folder')
    ap.add_argument(
        'quarantine', type=pathlib.Path,
        help=r'folder that directly contains Entries\ and ResourceData\ (e.g. C:\Quarantine)')
    ap.add_argument('-d', '--dump', action='store_true',
                    help='carve samples into a tar archive')
    ap.add_argument('-o', '--out', default='quarantine.tar',
                    help='output tar (default: quarantine.tar)')
    args = ap.parse_args()

    entries = parse_entries(args.quarantine)
    if not entries:
        print('No file-type entries found.')
        print(r'Make sure the path points at the folder holding Entries\ and ResourceData\.')
        return

    if not args.dump:
        for path, h in entries:
            print(f'{h}  {path}')
        print(f'\n{len(entries)} file entries  (add --dump to carve)')
        return

    tar = tarfile.open(args.out, 'w')
    seen = set()
    count = 0
    for path, h in entries:
        if h in seen:
            continue
        res = args.quarantine / 'ResourceData' / h[:2] / h
        if not res.exists():
            continue
        seen.add(h)
        with open(res, 'rb') as rf:
            malfile, malfile_len = unpack_malware(rf)
        sha = hashlib.sha256(malfile).hexdigest()
        info = tarfile.TarInfo(f'{h}_{path.name}')         # hash-prefixed: avoids name collisions
        info.size = malfile_len
        tar.addfile(info, io.BytesIO(malfile))
        count += 1
        print(f'{sha}  {malfile_len:>10}  {path.name}')
    tar.close()
    print(f'\n{count} samples -> {args.out}')


if __name__ == '__main__':
    main()